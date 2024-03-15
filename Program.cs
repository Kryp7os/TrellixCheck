using Microsoft.Win32;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace TrellixCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: TrellixCheck.exe [path/to/file]");
                return;
            }

            bool debug = false;
            if (args.Length == 2 && args[1].Contains("debug"))
            {
                debug = true;
            }

            string targetfile = args[0];
            Console.WriteLine("Target file: " + targetfile); // Debugging output
            if (!File.Exists(targetfile))
            {
                Console.WriteLine("[-] Can't access the target file: " + targetfile);
                Console.WriteLine("Current directory: " + Directory.GetCurrentDirectory()); // Debugging output
                Console.WriteLine("Available drives:");
                foreach (DriveInfo drive in DriveInfo.GetDrives()) // Debugging output
                {
                    Console.WriteLine(drive.Name);
                }
                return;
            }

            string originalFileDetectionStatus = Scan(targetfile).ToString();
            Console.WriteLine("Initial Detection Status: " + originalFileDetectionStatus); // Debugging output
            if (originalFileDetectionStatus.Equals("NoThreatFound"))
            {
                if (debug) { Console.WriteLine("Scanning the whole file first"); }
                Console.WriteLine("[+] No threat found in submitted file!");
                return;
            }

            if (!Directory.Exists(@"C:\Temp"))
            {
                Console.WriteLine(@"[-] C:\Temp doesn't exist. Creating it...");
                Directory.CreateDirectory(@"C:\Temp");
            }

            string testfilepath = @"C:\Temp\testfile.exe";
            byte[] originalfilecontents = File.ReadAllBytes(targetfile);
            int originalfilesize = originalfilecontents.Length;
            Console.WriteLine("Target file size: {0} bytes", originalfilecontents.Length);
            Console.WriteLine("Analyzing...\n");

            byte[] splitarray1 = new byte[originalfilesize / 2];
            Buffer.BlockCopy(originalfilecontents, 0, splitarray1, 0, originalfilecontents.Length / 2);
            int lastgood = 0;

            byte[] offendingBytes = null; // Store bytes causing the detection
            while (true)
            {
                Console.WriteLine("Inside the loop"); // Debugging output
                if (debug) { Console.WriteLine("Testing {0} bytes", splitarray1.Length); }

                // Additional debugging output
                Console.WriteLine("[DEBUG] Current split array size: " + splitarray1.Length);
                Console.WriteLine("[DEBUG] Last good index: " + lastgood);

                File.WriteAllBytes(testfilepath, splitarray1);
                string detectionStatus = Scan(testfilepath).ToString();
                Console.WriteLine("Detection Status: " + detectionStatus); // Debugging output

                // Additional debugging output
                Console.WriteLine("[DEBUG] Detection Status: " + detectionStatus);

                if (detectionStatus.Equals("ThreatFound"))
                {
                    // Store the bytes causing the detection
                    offendingBytes = (byte[])splitarray1.Clone();

                    // Continue splitting if a threat is found
                    byte[] temparray = HalfSplitter(splitarray1, lastgood);
                    Array.Resize(ref splitarray1, temparray.Length);
                    Array.Copy(temparray, splitarray1, temparray.Length);

                    // Additional debugging output
                    Console.WriteLine("[DEBUG] Splitting again...");
                }
                else if (detectionStatus.Equals("NoThreatFound"))
                {
                    // If no threat is found, exit the loop
                    Console.WriteLine("No threat found. Exiting...");
                    break;
                }
                else
                {
                    // If the file status is unknown, exit the loop
                    Console.WriteLine("Unknown file status. Exiting...");
                    break;
                }
            }

            // Output the bytes causing the last detection of threat
            if (offendingBytes != null)
            {
                Console.WriteLine("Exact byte causing detection found!");
                HexDump(offendingBytes);
            }
        }







        public static byte[] HalfSplitter(byte[] originalarray, int lastgood) //Will round down to nearest int
        {
            byte[] splitarray = new byte[(originalarray.Length - lastgood) / 2 + lastgood];
            if (originalarray.Length == splitarray.Length + 1)
            {
                Console.WriteLine("[!] Identified end of bad bytes at offset 0x{0:X} in the original file", originalarray.Length);
                Scan(@"C:\Temp\testfile.exe", true);
                byte[] offendingBytes = new byte[256];

                if (originalarray.Length < 256)
                {
                    Array.Resize(ref offendingBytes, originalarray.Length);
                    Buffer.BlockCopy(originalarray, originalarray.Length, offendingBytes, 0, originalarray.Length);
                }
                else
                {
                    Buffer.BlockCopy(originalarray, originalarray.Length - 256, offendingBytes, 0, 256);
                }
                HexDump(offendingBytes, 16);
                File.Delete(@"C:\Temp\testfile.exe");
                Environment.Exit(0);
            }

            // Debugging information
            Console.WriteLine("[DEBUG] Splitting file in progress...");
            Console.WriteLine("[DEBUG] Splitting {0} bytes from offset {1}", splitarray.Length, lastgood);
            Console.WriteLine("[DEBUG] Bytes within split array:");
            HexDump(originalarray.Skip(lastgood).Take(splitarray.Length).ToArray(), 16);

            Array.Copy(originalarray, splitarray, splitarray.Length);
            return splitarray;
        }


        public static byte[] Overshot(byte[] originalarray, int splitarraysize)
        {
            int newsize = (originalarray.Length - splitarraysize) / 2 + splitarraysize;
            if (newsize.Equals(originalarray.Length - 1))
            {
                Console.WriteLine("Exhausted the search. The binary looks good to go!");
                Environment.Exit(0);
            }
            byte[] newarray = new byte[newsize];
            Buffer.BlockCopy(originalarray, 0, newarray, 0, newarray.Length);
            return newarray;
        }

        public static ScanResult Scan(string targetfile, bool getsig = false)
        {
            if (!File.Exists(targetfile))
            {
                Console.WriteLine("Target file not found: " + targetfile);
                return ScanResult.FileNotFound;
            }

            var process = new Process();
            var trellixScanner = new ProcessStartInfo(@"C:\Temp\TrellixCheck\scan.exe")
            {
                Arguments = $"\"{targetfile}\"",
                CreateNoWindow = true,
                ErrorDialog = false,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true, // Redirect standard error for better error handling
                WindowStyle = ProcessWindowStyle.Hidden
            };

            process.StartInfo = trellixScanner;
            process.Start();
            process.WaitForExit(30000); // Wait 30s

            if (!process.HasExited)
            {
                Console.WriteLine("Scanner process did not exit within the timeout.");
                process.Kill();
                return ScanResult.Timeout;
            }

            // Read the output of the scanner and standard error
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();

            if (!string.IsNullOrEmpty(error))
            {
                // If there's an error message in the standard error output, handle it
                Console.WriteLine("Scanner Error: " + error);
                return ScanResult.Error;
            }

            // Check the output for specific patterns indicating threats
            Regex regex = new Regex(@"Possibly Infected:\.*\s+(\d+)");
            Match match = regex.Match(output);
            if (match.Success)
            {
                string countString = match.Groups[1].Value;
                if (int.TryParse(countString, out int count))
                {
                    Console.WriteLine("Number of possibly infected files: " + count);
                    if (count > 0)
                    {
                        return ScanResult.ThreatFound;
                    }
                    else
                    {
                        return ScanResult.NoThreatFound;
                    }
                }
                else
                {
                    // Unable to parse the count of possibly infected files
                    Console.WriteLine("Error parsing count of possibly infected files.");
                    return ScanResult.Error;
                }
            }

            // If the output does not contain "Possibly Infected", return Error
            Console.WriteLine("Scanner output does not contain 'Possibly Infected'.");
            return ScanResult.Error;
        }


        public enum ScanResult
        {
            [Description("Clean")]
            NoThreatFound,
            [Description("Possibly Infected")]
            ThreatFound,
            [Description("Not Scanned")]
            FileNotFound,
            [Description("Timeout")]
            Timeout,
            [Description("Error")]
            Error
        }

        public static void HexDump(byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null)
            {
                Console.WriteLine("[-] Empty array supplied. Something is wrong...");
            }
            int bytesLength = bytes.Length;

            char[] HexChars = "0123456789ABCDEF".ToCharArray();

            int firstHexColumn =
                  8                   // 8 characters for the address
                + 3;                  // 3 spaces

            int firstCharColumn = firstHexColumn
                + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
                + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                + 2;                  // 2 spaces 

            int lineLength = firstCharColumn
                + bytesPerLine           // - characters to show the ascii value
                + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            StringBuilder result = new StringBuilder(expectedLines * lineLength);

            for (int i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                int hexColumn = firstHexColumn;
                int charColumn = firstCharColumn;

                for (int j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        byte b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = (b < 32 ? '·' : (char)b);
                    }
                    hexColumn += 3;
                    charColumn++;
                }
                result.Append(line);
            }
            Console.WriteLine(result.ToString());
        }
    }
}
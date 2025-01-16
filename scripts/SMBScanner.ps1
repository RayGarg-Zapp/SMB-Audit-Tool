# This script includes an embedded C# class for SMB scanning and diagnostics. 
# The C# logic checks SMB versions (SMBv1, SMBv2, and SMBv3) on target endpoints, extracting key network and configuration details.

# Import the embedded C# logic as a source block.
$Source = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Runtime.InteropServices;

namespace Zapp.Scanners
{
    // Main class for scanning SMB configurations and capabilities on target servers.
    public class SmbScanner
	{
        // Struct representing the SMB Header for SMBv1 protocol.
        [StructLayout(LayoutKind.Explicit)]
		struct SMB_Header {
			[FieldOffset(0)]
			public UInt32 Protocol; // Identifies the protocol (e.g., 0xFF 'S' 'M' 'B').
			[FieldOffset(4)] 
			public byte Command; // SMB command.
			[FieldOffset(5)] 
			public int Status; // Response status.
			[FieldOffset(9)] 
			public byte  Flags; // Basic command flags.
			[FieldOffset(10)] 
			public UInt16 Flags2; // Extended flags.
			[FieldOffset(12)] 
			public UInt16 PIDHigh; // High part of Process ID.
			[FieldOffset(14)] 
			public UInt64 SecurityFeatures; // Security tokens.
			[FieldOffset(22)] 
			public UInt16 Reserved; // Reserved field.
			[FieldOffset(24)] 
			public UInt16 TID; // Tree ID.
			[FieldOffset(26)] 
			public UInt16 PIDLow; // Low part of Process ID.
			[FieldOffset(28)] 
			public UInt16 UID; // User ID.
			[FieldOffset(30)] 
			public UInt16 MID; // Multiplex ID.
		};

		// Struct representing the SMB2 Header for SMBv2 protocol.
		[StructLayout(LayoutKind.Explicit)]
		struct SMB2_Header {
			[FieldOffset(0)]
			public UInt32 ProtocolId; // Identifies the protocol (e.g., 0xFE 'S' 'M' 'B').
			[FieldOffset(4)]
			public UInt16 StructureSize; // Header size.
			[FieldOffset(6)]
			public UInt16 CreditCharge; // Credit charge for the request.
			[FieldOffset(8)]
			public UInt32 Status; // Response status.
			[FieldOffset(12)]
			public UInt16 Command; // SMB2 command.
			[FieldOffset(14)]
			public UInt16 CreditRequest_Response; // Credits granted or requested.
			[FieldOffset(16)]
			public UInt32 Flags; // Flags indicating request type.
			[FieldOffset(20)]
			public UInt32 NextCommand; // Next command in the chain.
			[FieldOffset(24)]
			public UInt64 MessageId; // Unique message ID.
			[FieldOffset(32)]
			public UInt32 Reserved; // Reserved field.
			[FieldOffset(36)]
			public UInt32 TreeId; // Tree ID for the session.
			[FieldOffset(40)]
			public UInt64 SessionId; // Session ID.
			[FieldOffset(48)]
			public UInt64 Signature1; // Part of the request signature.
			[FieldOffset(56)]
			public UInt64 Signature2; // Part of the request signature.
		}

        // Struct representing an SMB2 Negotiate Request.
        [StructLayout(LayoutKind.Explicit)]
		struct SMB2_NegotiateRequest
		{
			[FieldOffset(0)]
			public UInt16 StructureSize; // Fixed size of this request.
			[FieldOffset(2)]
			public UInt16 DialectCount; // Number of dialects supported by the client.
			[FieldOffset(4)]
			public UInt16 SecurityMode; // Security mode (e.g., signing enabled).
			[FieldOffset(6)]
			public UInt16 Reserved; // Reserved for alignment.
			[FieldOffset(8)]
			public UInt32 Capabilities; // Capabilities of the client.
			[FieldOffset(12)]
			public Guid ClientGuid; // Unique identifier for the client.
			[FieldOffset(28)]
			public UInt64 ClientStartTime; // Optional client start time.
			[FieldOffset(36)]
			public UInt16 DialectToTest; // Dialect to be tested for negotiation.
		}

		// Constants for SMB commands and flags.
		const int SMB_COM_NEGOTIATE	= 0x72;
		const int SMB2_NEGOTIATE = 0;

		const int SMB_FLAGS_CASE_INSENSITIVE = 0x08;
		const int SMB_FLAGS_CANONICALIZED_PATHS = 0x10;

		const int SMB_FLAGS2_LONG_NAMES = 0x0001;
		const int SMB_FLAGS2_EAS = 0x0002;
		const int SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED = 0x0010;
		const int SMB_FLAGS2_IS_LONG_NAME = 0x0040;
		const int SMB_FLAGS2_ESS = 0x0800;
		const int SMB_FLAGS2_NT_STATUS = 0x4000;
		const int SMB_FLAGS2_UNICODE = 0x8000;

		const int SMB_DB_FORMAT_DIALECT = 0x02;

		// Generates an SMBv1 header for a given command.
		static byte[] GenerateSmbHeaderFromCommand(byte command)
		{
			SMB_Header header = new SMB_Header();
			header.Protocol = 0x424D53FF; // SMB protocol signature.
			header.Command = command;
			header.Status = 0; // No error by default.
			header.Flags = SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS;
			header.Flags2 = SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EAS | SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_ESS | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE;
			header.PIDHigh = 0;
			header.SecurityFeatures = 0;
			header.Reserved = 0;
			header.TID = 0xffff; // Default TID.
			header.PIDLow = 0xFEFF; // Default PID.
			header.UID = 0;
			header.MID = 0;
			return getBytes(header);
		}

		// Generate bytes for an SMBv2 header with a specific command.
		static byte[] GenerateSmb2HeaderFromCommand(byte command)
		{
			SMB2_Header header = new SMB2_Header();
			header.ProtocolId = 0x424D53FE; // SMB2 protocol signature.
			header.Command = command; // Command for negotiation.
			header.StructureSize = 64; // Fixed size.
			header.MessageId = 0; // Default message ID.
			header.Reserved = 0xFEFF; // Reserved for compatibility.
			return getBytes(header);
		}

		// Converts a structure to a byte array for transmission.
		static byte[] getBytes(object structure)
		{
			int size = Marshal.SizeOf(structure);
			byte[] arr = new byte[size];

			IntPtr ptr = Marshal.AllocHGlobal(size);
			Marshal.StructureToPtr(structure, ptr, true);
			Marshal.Copy(ptr, arr, 0, size);
			Marshal.FreeHGlobal(ptr);
			return arr;
		}

		// Encodes a dialect string into an SMB-compliant format.
		static byte[] getDialect(string dialect)
		{
			byte[] dialectBytes = Encoding.ASCII.GetBytes(dialect);
			byte[] output = new byte[dialectBytes.Length + 2];
			output[0] = 2; // Prefix for dialects.
			output[output.Length - 1] = 0; // Null-terminate.
			Array.Copy(dialectBytes, 0, output, 1, dialectBytes.Length);
			return output;
		}

		// Creates a negotiation message with specified dialects.
		static byte[] GetNegotiateMessage(byte[] dialect)
		{
			byte[] output = new byte[dialect.Length + 3];
			output[0] = 0; // Padding.
			output[1] = (byte) dialect.Length; // Length of dialect string.
			output[2] = 0; // Padding.
			Array.Copy(dialect, 0, output, 3, dialect.Length);
			return output;
		}

		// Negotiation message for SMBv2.
		static byte[] GetNegotiateMessageSmbv2(int DialectToTest)
		{
			SMB2_NegotiateRequest request = new SMB2_NegotiateRequest();
			request.StructureSize = 36; // Fixed size of SMBv2 negotiation request.
			request.DialectCount = 1; // Single dialect to test.
			request.SecurityMode = 1; // Signing required.
			request.ClientGuid = Guid.NewGuid(); // Unique client identifier.
			request.DialectToTest = (UInt16) DialectToTest; // Dialect under test.
			return getBytes(request);
		}

		// Combines SMB header and body into a complete packet.
		static byte[] GetNegotiatePacket(byte[] header, byte[] smbPacket)
		{
			byte[] output = new byte[smbPacket.Length + header.Length + 4];
			output[0] = 0; // NetBIOS header padding.
			output[1] = 0;
			output[2] = 0;
			output[3] = (byte)(smbPacket.Length + header.Length); // Length of combined packet.
			Array.Copy(header, 0, output, 4, header.Length);
			Array.Copy(smbPacket, 0, output, 4 + header.Length, smbPacket.Length);
			return output;
		}

		// Verifies if a server supports a specific SMB dialect for SMBv1.
		public static bool DoesServerSupportDialect(string server, string dialect)
		{
			Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect);
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445); // Connect to SMB port.
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmbHeaderFromCommand(SMB_COM_NEGOTIATE);
				byte[] dialectEncoding = getDialect(dialect);
				byte[] negotiatemessage = GetNegotiateMessage(dialectEncoding);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();

				// Validate response for supported dialect.
				byte[] netbios = new byte[4];
				if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
				byte[] negotiateresponse = new byte[3];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
				if (negotiateresponse[1] == 0 && negotiateresponse[2] == 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Not supported");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb1 is not supported on " + server);
			}
		}

		// Verifies if a server supports a specific SMB dialect for SMBv2.
		public static bool DoesServerSupportDialectWithSmbV2(string server, int dialect)
		{
			Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2"));
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445); // Connect to SMB port.
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmb2HeaderFromCommand(SMB2_NEGOTIATE);
				byte[] negotiatemessage = GetNegotiateMessageSmbv2(dialect);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();

				// Validate response for supported dialect.
				byte[] netbios = new byte[4];
				if( stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB2_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
				if (smbHeader[8] != 0 || smbHeader[9] != 0 || smbHeader[10] != 0 || smbHeader[11] != 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
					return false;
				}
				byte[] negotiateresponse = new byte[6];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
				int selectedDialect = negotiateresponse[5] * 0x100 + negotiateresponse[4];
				if (selectedDialect == dialect)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Not supported via not returned dialect");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb2 is not supported on " + server);
			}
		}

		// Determines if a server supports SMBv1.
		public static bool SupportSMB1(string server)
		{
			try
			{
				return DoesServerSupportDialect(server, "NT LM 0.12");
			}
			catch (Exception)
			{
				return false;
			}
		}

		// Determines if a server supports SMBv2.
		public static bool SupportSMB2(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0202) || DoesServerSupportDialectWithSmbV2(server, 0x0210));
			}
			catch (Exception)
			{
				return false;
			}
		}

		// Determines if a server supports SMBv3.
		public static bool SupportSMB3(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0300) || DoesServerSupportDialectWithSmbV2(server, 0x0302) || DoesServerSupportDialectWithSmbV2(server, 0x0311));
			}
			catch (Exception)
			{
				return false;
			}
		}

		// Header for CSV output.
		public static string GetCsvHeader()
		{
			return "Computer\tSMB Port Open\tSMB1(NT LM 0.12)\tSMB2(0x0202)\tSMB2(0x0210)\tSMB3(0x0300)\tSMB3(0x0302)\tSMB3(0x0311)";
		}

		// Generates CSV row data for a computer.
		public static string GetCsvData(string computer)
		{
			bool isPortOpened = true;
			bool SMBv1 = false;
			bool SMBv2_0x0202 = false;
			bool SMBv2_0x0210 = false;
			bool SMBv2_0x0300 = false;
			bool SMBv2_0x0302 = false;
			bool SMBv2_0x0311 = false;
			try
			{
				try
				{
					SMBv1 = DoesServerSupportDialect(computer, "NT LM 0.12");
				}
				catch (ApplicationException)
				{
				}
				try
				{
					SMBv2_0x0202 = DoesServerSupportDialectWithSmbV2(computer, 0x0202);
					SMBv2_0x0210 = DoesServerSupportDialectWithSmbV2(computer, 0x0210);
					SMBv2_0x0300 = DoesServerSupportDialectWithSmbV2(computer, 0x0300);
					SMBv2_0x0302 = DoesServerSupportDialectWithSmbV2(computer, 0x0302);
					SMBv2_0x0311 = DoesServerSupportDialectWithSmbV2(computer, 0x0311);
				}
				catch (ApplicationException)
				{
				}
			}
			catch (Exception)
			{
				isPortOpened = false;
			}
			return computer + "\t" + (isPortOpened ? "Yes" : "No") + "\t" + (SMBv1 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0202 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0210 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0300 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0302 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0311 ? "Yes" : "No");
		}
		
        // Prints CSV data to console for a computer.
        public static void GetCsv(string computer)
        {
            Console.WriteLine(GetCsvHeader());
            Console.WriteLine(GetCsvData(computer));
        }
	}
}
"@

# Load the embedded C# code as a PowerShell type.
Add-Type -TypeDefinition $Source

# Example usage: Retrieves SMB compatibility for the specified IP.
# [Zapp.Scanners.SmbScanner]::GetCsv("192.168.0.25")

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.IO;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Timers;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Messaging;
using System.Text;

namespace ProcessBouncerService
{

	public partial class Service1 : ServiceBase
	{

		string logPath;
		string[] suspicious;
		string[] suspiciousParents;
		string[] suspiciousExePath;
		string[] ext1;
		string[] ext2;
		string[] whitelistedPath;
		string[] whitelistedProcesses;
		string[] whitelistedScripts;

		bool debug = false;
		bool bulkCheck = false;
		bool checkObfuscation = false;
		bool gui;

		char[] dec;
		char[] sepc;
		char[] mhc;
		char[] spc;
		char[] sppc;
		char[] mdsc;

		List<string> sig = new List<string>();
		List<string> dynSig = new List<string>();
		string dynSigDirectory;
		string sigDirectory;

		MessageQueue pbq;
		MessagePriority highest = MessagePriority.Highest;
		MessagePriority high = MessagePriority.High;
		MessagePriority normal = MessagePriority.Normal;
		MessagePriority low = MessagePriority.Low;

		Timer timerBulk = new Timer();
		int intervalBulk;

		[Flags]
		public enum ProcessAccess : uint
		{
			Terminate = 0x00000001,
			CreateThread = 0x00000002,
			VMOperation = 0x00000008,
			VMRead = 0x00000010,
			VMWrite = 0x00000020,
			DupHandle = 0x00000040,
			SetInformation = 0x00000200,
			QueryInformation = 0x00000400,
			SuspendResume = 0x00000800,
			Synchronize = 0x00100000,
			All = 0x001F0FFF
		}

		[DllImport("ntdll.dll", EntryPoint = "NtSuspendProcess", SetLastError = true)]
		public static extern uint SuspendProcess(IntPtr processHandle);

		[DllImport("ntdll.dll", EntryPoint = "NtResumeProcess", SetLastError = true)]
		public static extern uint ResumeProcess(IntPtr processHandle);

		[DllImport("ntdll.dll", EntryPoint = "NtTerminateProcess", SetLastError = true)]
		public static extern uint TerminateProcess(IntPtr processHandle);

		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(ProcessAccess dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool CloseHandle(IntPtr hObject);

		public Service1()
		{
			InitializeComponent();
			this.ServiceName = "ProcessBouncerService";
		}

		protected override void OnStart(string[] args)
		{
			logPath = @"C:\ProcessBouncer";
			//ToDo 
			/*
			if not whitlelistFile{
				generate whitelistFile from History
			}
			else{
				read whitelistFile
			}
			*/

			//ToDo: Remove whitespaces in list like processes, ext1, ext2

			var guiProc = Process.GetProcessesByName("ProcessBouncerGUI");
			if (guiProc.Length > 0){
				gui = true;
			}
			else{
				gui = false;
			}
			
			if (gui)
			{
				if(MessageQueue.Exists(@".\private$\pbq"))
				{
					pbq = new MessageQueue(@".\private$\pbq");
				}
				else
				{
					pbq = MessageQueue.Create(@".\private$\pbq");
				}
			}

			//Reading ConfigFile
			int counter = 1;
			string[] lines;
			if (File.Exists(@"C:\ProcessBouncer\safeConfig.txt"))
			{
				lines = DecryptFile(@"C:\ProcessBouncer\safeConfig.txt");
			}
			else
			{
				lines = System.IO.File.ReadAllLines(@"C:\ProcessBouncer\config.txt");
			}

			foreach(string line in lines)
			{
				if(line.StartsWith("#"))
				{
					continue;
				}

				switch(counter)
				{
					case 1:
						logPath = line;
						break;
					case 2:
						suspicious = line.Split(',');
						break;
					case 3:
						suspiciousParents = line.Split(',');
						break;
					case 4:
						suspiciousExePath = line.Split(',');
						break;
					case 5:
						ext1 = line.Split(',');
						break;
					case 6:
						ext2 = line.Split(',');
						break;
					case 7:
						whitelistedPath = line.Split(',');
						break;
					case 8:
						whitelistedProcesses = line.Split(',');
						break;
					case 9:
						whitelistedScripts = line.Split(',');
						break;
					case 10:
						int bulkCheckInt = Convert.ToInt32(line);
						if (bulkCheckInt == 1){
							bulkCheck = true;
						}
						break;
					case 11:
						intervalBulk = Convert.ToInt32(line);
						break;
					case 12:
						dec = line.ToCharArray(0,4);
						break;
					case 13:
						sepc = line.ToCharArray(0,4);
						break;
					case 14:
						mhc = line.ToCharArray(0,4);
						break;
					case 15:
						spc = line.ToCharArray(0,4);
						break;
					case 16:
						sppc = line.ToCharArray(0,4);
						break;
					case 17:
						sigDirectory = line;
						break;
					case 18:
						dynSigDirectory = line;
						break;
					case 19:
						mdsc = line.ToCharArray(0,4);
						break;
					case 20:
						int obfusInt = Convert.ToInt32(line);
						if (obfusInt == 1){
							checkObfuscation = true;
						}
						break;
					case 21:
						int debugInt = Convert.ToInt32(line);
						if (debugInt == 1){
							debug = true;
						}
						break;
				}
				counter++;
			}

			//Reading Signatures
			DirectoryInfo dSig = new DirectoryInfo(sigDirectory);
		
			foreach (var file in dSig.GetFiles())
			{
      			getSigHash(file.FullName);
			}

			//Reading dynamic signatures
			DirectoryInfo dDynSig = new DirectoryInfo(dynSigDirectory);
			
			foreach (var file in dDynSig.GetFiles("*.yara"))
			{
      			dynSig.Add(getDynSigFromYara(file.FullName));
			}

			WriteLog("Service has been started");
			//Watch for newly started Processes
			ManagementEventWatcher eventWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
			eventWatcher.EventArrived += new EventArrivedEventHandler(CheckProcess);
			eventWatcher.Start();

			//Check for bilk writing with a timer
			if (bulkCheck)
			{
				timerBulk.Elapsed += new ElapsedEventHandler(CheckTransferProcess);
				timerBulk.Interval = intervalBulk;
				timerBulk.Enabled = true;
			}
		}

		private void CheckProcess(object sender, EventArrivedEventArgs e)
		{
			object pid = e.NewEvent.Properties["ProcessID"].Value;

			//Get more Information about Process from WMI
			WqlObjectQuery query = new WqlObjectQuery(String.Format("SELECT * FROM Win32_Process WHERE ProcessId={0}", pid));
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
			ManagementObjectCollection collection = searcher.Get();
			foreach (ManagementObject tmp in collection)
			{
				object procName = tmp.Properties["Caption"].Value;
				object ppid = tmp.Properties["ParentProcessId"].Value;
				object cmd = tmp.Properties["CommandLine"].Value;
				object exePath = tmp.Properties["ExecutablePath"].Value;
				object name = tmp.Properties["Name"].Value;

				bool whitelistedScript = false;

				string der;
				bool sepr;
				bool mhr;
				bool spr;
				bool sppr;
				bool mdsr;
				bool obfus;

				//Stop when Process is whitlisted
				if (whitelistedProcesses.Contains(procName))
				{
					break;
				}

				//Stop if Script is whitlisted
				foreach (string s in whitelistedScripts)
				{
					string pattern = String.Format(@"\b{0}\b", s);
					MatchCollection tmpMatch = Regex.Matches(cmd.ToString(), pattern);
					if (tmpMatch.Count > 0)
					{
						whitelistedScript = true;
					}
				}
				if (whitelistedScript)
				{
					break;
				}

				if (debug)
				{
					WriteLog(String.Format("Checking - {0}({1})", procName, pid));
				}

				//Checking
				if (spc[0] == '1'){
					spr = suspiciousProcessFunc(procName.ToString(), name.ToString());
				}
				else
				{
					spr = false;
				}
				if (sppc[0] == '1')
				{
					sppr = suspiciousParentProcessFunc((uint)ppid);
				}
				else
				{
					sppr = false;
				}
				if (mhc[0] == '1')
				{
					mhr = maliciousHashFunc(exePath.ToString());
				}
				else
				{
					mhr = false;
				}
				if (sepc[0] == '1')
				{
					sepr = suspiciousExePathFunc(cmd.ToString());
				}
				else
				{
					sepr = false;
				}
				if (dec[0] == '1')
				{
					der = doubleExtFunc(cmd.ToString());
				}
				else
				{
					der = "false";
				}
				if (mdsc[0] == '1')
				{
					mdsr = dynamicSignatureFunc(cmd.ToString());
				}
				else
				{
					mdsr = false;
				}
				if (checkObfuscation)
				{
					obfus = checkObfuscationFunc(cmd.ToString());
				}
				else
				{
					obfus = false;
				}

				//Logging
				if (mhc[3] == '1' && mhr){
					WriteLog(String.Format("Signature found! - MALWARE! - {0}", exePath));
				}
				if (mdsc[3] == '1' && mdsr){
					WriteLog(String.Format("Dynamic Signature found! - MALWARE! - {0}", cmd));
				}
				if (sepc[3] == '1' && sepr){
					WriteLog(String.Format("SuspiciousExecutionPath - {0}({1}) - {2}", procName, pid, cmd));
				}
				if (dec[3] == '1' && der != "false"){
					WriteLog(String.Format("DoubleExtension - {0}({1}) - {2}", procName, pid, der));
				}
				if (spc[3] == '1' && spr)
				{
					WriteLog(String.Format("SuspiciousProcess - {0}({1})", procName, pid));
				}
				if (sppc[3] == '1' && sppr){
					WriteLog(String.Format("SuspiciousProcess - {0}({1}) - started from - ({2})", procName, pid, ppid));
				}
				if (obfus){
					WriteLog("Obfuscated cmdLine");
				}

				//Reaction
				if (gui)
				{
					if ((mhc[1] == '1' && mhr) || (mdsc[1] == '1' && mdsr) || (sepc[1] == '1' && sepr) || (dec[1] == '1' && der != "false") || (spc[1] == '1' && spr) || (sppc[1] == '1' && sppr)){
						KillProc((uint)pid);
					}
					else if ((mhc[1] == '4' && mhr) || (mdsc[1] == '4' && mdsr) || (sepc[1] == '4' && sepr) || (dec[1] == '4' && der != "false") || (spc[1] == '4' && spr) || (sppc[1] == '4' && sppr)){
						string userReturn = ask((uint)pid, exePath.ToString());
						if (userReturn == "K"){
							KillProc((uint)pid);
							WriteLog(String.Format("User killed - {0}({1})", procName, pid));
						}
						else if (userReturn == "S"){
							SuspendProc((uint)pid);
							WriteLog(String.Format("User suspends - {0}({1})", procName, pid));
						}
						else if (userReturn == "R"){
							ResumeProc((uint)pid);
							WriteLog(String.Format("User resumed - {0}({1})", procName, pid));
						}
					}
					else if ((mhc[1] == '2' && mhr) || (mdsc[1] == '2' && mdsr) || (sepc[1] == '2' && sepr) || (dec[1] == '2' && der != "false") || (spc[1] == '2' && spr) || (sppc[1] == '2' && sppr)){
						SuspendProc((uint)pid);
					}
				}
				else
				{
					if ((mhc[2] == '1' && mhr) || (mdsc[2] == '1' && mdsr) || (sepc[2] == '1' && sepr) || (dec[2] == '1' && der != "false") || (spc[2] == '1' && spr) || (sppc[2] == '1' && sppr)){
						KillProc((uint)pid);
					}
					else if ((mhc[2] == '2' && mhr) || (mdsc[2] == '2' && mdsr) || (sepc[2] == '2' && sepr) || (dec[2] == '2' && der != "false") || (spc[2] == '2' && spr) || (sppc[2] == '2' && sppr)){
						SuspendProc((uint)pid);
					}
				}

				if (debug)
				{
					WriteLog(String.Format("All Good! - {0}({1})", procName, pid));
				}
			}
			return;
		}

		private void CheckTransferProcess(object source, ElapsedEventArgs e)
		{
			if (debug)
			{
				WriteLog("Checking BulkWriting");
			}
			//Get Processes with high writingOperations
			ManagementObjectSearcher searcher = new ManagementObjectSearcher(new WqlObjectQuery("SELECT * FROM Win32_Process WHERE WriteTransferCount > 20000000 and WriteOperationCount > 10 and UserModeTime > 10000000"));
			//Checks for 10 WriteOperations done and a speed of 20MB/sec
			ManagementObjectCollection collection = searcher.Get();
			foreach (ManagementObject tmp in collection)
			{
				object procName = tmp.Properties["Caption"].Value;
				object pid = tmp.Properties["ProcessId"].Value;
				object ppid = tmp.Properties["ParentProcessId"].Value;
				object cmd = tmp.Properties["CommandLine"].Value;
				object exePath = tmp.Properties["ExecutablePath"].Value;
				object name = tmp.Properties["Name"].Value;

				bool whitelistedScript = false;

				//Stop if Process is whitelisted
				if (whitelistedProcesses.Contains(procName))
				{
					break;
				}

				//Stop if Script is whitelisted
				foreach (string s in whitelistedScripts)
				{
					string pattern = String.Format(@"\b{0}\b", s);
					MatchCollection tmpMatch = Regex.Matches(cmd.ToString(), pattern);
					if (tmpMatch.Count > 0)
					{
						whitelistedScript = true;
					}
				}
				if (whitelistedScript)
				{
					break;
				}

				//ToDo
				SuspendProc((uint)pid);
				WriteLog(String.Format("{0}({1}) does bulk writing", procName, pid));
				if (gui)
				{
					string userReturn = ask((uint)pid, procName.ToString());
					if (userReturn == "K"){
						KillProc((uint)pid);
						WriteLog(String.Format("User killed - {0}({1})", procName, pid));
					}
					else if (userReturn == "S"){
						SuspendProc((uint)pid);
						WriteLog(String.Format("User suspends - {0}({1})", procName, pid));
					}
					else if (userReturn == "R"){
						ResumeProc((uint)pid);
						WriteLog(String.Format("User resumed - {0}({1})", procName, pid));
					}
				}
				else{
					KillProc((uint)pid);
				}
			}
			return;
		}

		private bool suspiciousExePathFunc(string cmd)
		{
			foreach (string s in suspiciousExePath)
			{
				string pattern = String.Format(@"{0}", s);
				MatchCollection tmpMatch = Regex.Matches(cmd, pattern);
				if (tmpMatch.Count > 0)
				{
					return true;
				}
			}
			return false;
		}

		//Checking for double Extensions like evil.doc.exe
		private string doubleExtFunc(string cmd)
		{
			string doubleExtPattern = @"\\[A-Za-z0-9]*\.[A-Za-z0-9]*\.[A-Za-z0-9]*(?!\.)\b";
			foreach(Match match in Regex.Matches(cmd,doubleExtPattern))
			{
				string[] parts = match.ToString().Split('.');
				if (ext2.Contains(parts[parts.Length - 1]) && ext1.Contains(parts[parts.Length - 2]))
				{
					return match.ToString();
				}
			}
			return "false";
		}

		private bool suspiciousProcessFunc(string procName, string name)
		{
			if (suspicious.Contains(procName) || suspicious.Contains(name))
			{
				return true;
			}
			return false;
		}

		private bool suspiciousParentProcessFunc(uint ppid)
		{
			WqlObjectQuery parentQuery = new WqlObjectQuery(String.Format("SELECT Caption FROM Win32_Process WHERE ProcessId={0}", ppid));
			ManagementObjectSearcher searcherParent = new ManagementObjectSearcher(parentQuery);
			ManagementObjectCollection collectionParent = searcherParent.Get();
			string parentProcName = "";
			foreach (ManagementObject tmpParent in collectionParent)
			{
				parentProcName = tmpParent.Properties["Caption"].ToString();
				if (suspiciousParents.Contains(parentProcName))
				{
					return true;
				}
			}
			return false;
		}

		//Checking for a known malware signature
		private bool maliciousHashFunc(string exePath)
		{
			string suspMD5 = CalculateMD5(exePath);
			if (sig.Contains(suspMD5))
			{
				return true;
			}
			return false;
		}

		private bool dynamicSignatureFunc(string cmd)
		{
			string PathPattern = @"[A-Z]\:\\[\w(?\\)]*.\w*";
			MatchCollection cmdFiles = Regex.Matches(cmd, PathPattern);
			foreach (var file in cmdFiles){
				if (Regex.Matches(file.ToString(), @"\.txt").Count > 0)
				{
					FileStream fs = new FileStream(file.ToString(), FileMode.Open);
					int hexIn;
					String hex = "";

					for (int i = 0; (hexIn = fs.ReadByte()) != -1; i++)
					{
						hex += string.Format("{0:X2}", hexIn);
					}

					foreach (string pattern in dynSig)
					{
						if (Regex.Matches(hex, pattern, RegexOptions.IgnoreCase).Count > 0)
						{
							return true;
						}
					}
				}
			}
			return false;
		}

		private void getSigHash(string filename)
		{
			string[] fileContent = System.IO.File.ReadAllLines(filename);
			foreach(string s in fileContent)
			{
				sig.Add(s);
			}
			return;
		}

		private string CalculateMD5(string filename)
		{
    		using (var md5 = MD5.Create())
    		{
        		using (var stream = File.OpenRead(filename))
        		{
            		var hash = md5.ComputeHash(stream);
            		return BitConverter.ToString(hash).Replace("-", "").ToLower();
        		}
    		}
		}

		private string getDynSigFromYara(string dataFile)
		{
			string[] fileContent = System.IO.File.ReadAllLines(dataFile);
			foreach (string s in fileContent)
			{
				if (Regex.Matches(s,@"\$img =").Count > 0)
				{
					string result = s.Substring(9);
					result = result.Replace("{", string.Empty);
					result = result.Replace("}", string.Empty);
					result = result.Replace("-", ",");
					result = result.Replace(" [", "[0-9a-f]{");
					result = result.Replace("] ", "}");
					result = result.Replace(" ",string.Empty);
					return result;
				}
			}
			return "Error";
		}

		private bool checkObfuscationFunc(string cmd)
		{
			//Check with Kullback-Leiber-Divergenz for informationgain
			return false;
		}

		private string ask(uint pid, string exePath){
			SuspendProc(pid);
			sendMsg(exePath);
			Message userRet = rcvMsg();
			return userRet.Label.ToString();
		}

		private void sendMsg(string lbl)
		{
			Message message = new Message();
			message.Label = lbl;
			try
			{
				pbq.Send(message);
			}
			catch (MessageQueueException e)
			{
				WriteLog(e.Message);
			}
			return;
		}

		private Message rcvMsg()
		{
			//pbq.MessageReadPropertyFilter.Priority = true;
			//pbq.Formatter = new XmlMessageFormatter(new Type[] {typeof(string)});
			try
			{
				Message message = pbq.Receive();
				return message;
			}
			catch (MessageQueueException e)
			{
				WriteLog(e.Message);
			}
			catch (InvalidOperationException e)
			{
				WriteLog(e.Message);
			}
			Message empty = new Message();
			return empty;
		}

		private void SuspendProc(uint procId)
		{
			IntPtr maliciousProc = OpenProcess(ProcessAccess.SuspendResume, false, procId);
			if (maliciousProc != IntPtr.Zero)
			{
				uint suspendProc = SuspendProcess(maliciousProc);
				if (suspendProc == 0)
				{
					CloseHandle(maliciousProc);
					WriteLog(String.Format("SuspendedProcess - {0}", procId));
					return;
				}
				return;
			}
			return;
		}

		private void ResumeProc(uint procId)
		{
			IntPtr benignProc = OpenProcess(ProcessAccess.SuspendResume, false, procId);
			if(benignProc != IntPtr.Zero)
			{
				uint resumProc = ResumeProcess(benignProc);
				if(resumProc == 0)
				{
					CloseHandle(benignProc);
					WriteLog(String.Format("ResumedProcess - {0}", procId));
					return;
				}
				return;
			}
			return;
		}

		private void KillProc(uint procId)
		{
			IntPtr maliciousProc = OpenProcess(ProcessAccess.Terminate, false, procId);
			if(maliciousProc != IntPtr.Zero)
			{
				uint killProc = TerminateProcess(maliciousProc);
				if(killProc == 0)
				{
					CloseHandle(maliciousProc);
					WriteLog(String.Format("KilledProcess - {0}", procId));
					return;
				}
				return;
			}
			return;
		}

		protected override void OnStop()
		{
			WriteLog("Service has been stopped.");
			//eventWatcher.Stop();
		}

		private void WriteLog(string logMessage, bool addTimeStamp = true)
		{
			if (!Directory.Exists(logPath))
				Directory.CreateDirectory(logPath);

			var filePath = String.Format("{0}\\{1}_{2}.txt", logPath, ServiceName, DateTime.Now.ToString("yyyyMMdd", CultureInfo.CurrentCulture));

			if (addTimeStamp)
				logMessage = String.Format("[{0}] - {1}{2}",
					DateTime.Now.ToString("HH:mm:ss", CultureInfo.CurrentCulture), logMessage, Environment.NewLine);

			File.AppendAllText(filePath, logMessage);
		}

		private string[] DecryptFile(string inputFile)
		{
			string[] result;
			byte[] dencryptedBytes = null;
			byte[] data = File.ReadAllBytes(inputFile);

			byte[] passBytes = Encoding.ASCII.GetBytes("b1bHhco64JQ14Pg4");
			byte[] saltBytes = Encoding.ASCII.GetBytes("xCZmKg7Kv1xpFUEdlgpXaSvJ186RvB");

			// create a key from the password and salt, use 32K iterations
			var key = new Rfc2898DeriveBytes(passBytes, saltBytes, 32768);
			using (Aes aes = new AesManaged())
			{
				// set the key size to 256
				aes.KeySize = 256;
				aes.Key = key.GetBytes(aes.KeySize / 8);
				aes.IV = key.GetBytes(aes.BlockSize / 8);
				using (MemoryStream ms = new MemoryStream())
				{
					using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
					{
						cs.Write(data, 0, data.Length);
						cs.Close();
					}
					dencryptedBytes = ms.ToArray();
				}
				var str = System.Text.Encoding.Default.GetString(dencryptedBytes);
				result = str.Split(new[] { "\r\n", "\r", "\n" },StringSplitOptions.None);
			}
			return result;
		}

	}
}
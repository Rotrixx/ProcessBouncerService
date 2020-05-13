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
using System.Threading;

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
		string[] whitelistedPaths;
		string[] whitelistedProcesses;
		string[] whitelistedScripts;

		bool debug = false;
		bool bulkCheck = false;
		bool gui;
		bool guiAtStartUp;

		char[] dec;
		char[] sepc;
		char[] mhc;
		char[] spc;
		char[] sppc;
		char[] mdsc;
		char[] obfusc;

		List<string> sig = new List<string>();
		List<string> dynSig = new List<string>();
		string dynSigDirectory;
		string sigDirectory;

		MessageQueue pbq;

		BackgroundWorker backgroundWorker1 = new BackgroundWorker();
		BackgroundWorker backgroundWorker2 = new BackgroundWorker();
		BackgroundWorker backgroundWorker3 = new BackgroundWorker();
		BackgroundWorker backgroundWorker4 = new BackgroundWorker();
		BackgroundWorker backgroundWorker5 = new BackgroundWorker();

		System.Timers.Timer timerBulk = new System.Timers.Timer();
		System.Timers.Timer timerRecheck = new System.Timers.Timer();
		int intervalBulk;
		int intervalRecheck = 300000; //5min

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

			var guiProc = Process.GetProcessesByName("ProcessBouncerGUI");
			if (guiProc.Length > 0)
			{
				gui = true;
				guiAtStartUp = true;
			}
			else
			{
				gui = false;
				guiAtStartUp = false;
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
						whitelistedPaths = line.Split(',');
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
						obfusc = line.ToCharArray(0,4);
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

			backgroundWorker1.DoWork += CheckProcess;
			backgroundWorker2.DoWork += CheckProcess;
			backgroundWorker3.DoWork += CheckProcess;
			backgroundWorker4.DoWork += CheckProcess;
			backgroundWorker5.DoWork += CheckProcess;

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
			eventWatcher.EventArrived += new EventArrivedEventHandler(checkProcessAsync);
			eventWatcher.Start();

			//Check for bulk writing with a timer
			if (bulkCheck)
			{
				timerBulk.Elapsed += new ElapsedEventHandler(CheckTransferProcess);
				timerBulk.Interval = intervalBulk;
				timerBulk.Enabled = true;
			}

			timerRecheck.Elapsed += new ElapsedEventHandler(checkForGui);
			timerRecheck.Interval = intervalRecheck;
			timerRecheck.Enabled = true;
		}

		private void checkProcessAsync(object sender, EventArrivedEventArgs e)
		{
			object pid = e.NewEvent.Properties["ProcessID"].Value;

			if (backgroundWorker1.IsBusy != true)
			{
				WriteLog("Worker1");
				backgroundWorker1.RunWorkerAsync(argument: pid);
			}
			else if (backgroundWorker2.IsBusy != true)
			{
				WriteLog("Worker2");
				backgroundWorker2.RunWorkerAsync(argument: pid);
			}
			else if (backgroundWorker3.IsBusy != true)
			{
				WriteLog("Worker3");
				backgroundWorker3.RunWorkerAsync(argument: pid);
			}
			else if (backgroundWorker4.IsBusy != true)
			{
				WriteLog("Worker4");
				backgroundWorker4.RunWorkerAsync(argument: pid);
			}
			else if (backgroundWorker5.IsBusy != true)
			{
				WriteLog("Worker5");
				backgroundWorker5.RunWorkerAsync(argument: pid);
			}
			else{
				WriteLog("TempWorker");
				BackgroundWorker tempBackgroundWorker = new BackgroundWorker();
				tempBackgroundWorker.DoWork += CheckProcess;
				tempBackgroundWorker.RunWorkerAsync(argument: pid);
			}
			return;
		}

		private void CheckProcess(object sender, DoWorkEventArgs e)
		{
			object pid = e.Argument;
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
				bool whitelistedPath = false;

				string der = "false";
				bool sepr = false;
				bool mhr = false;
				bool spr = false;
				bool sppr = false;
				bool mdsr = false;
				bool obfusr = false;

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

				//Whitelisted Path
				foreach (string s in whitelistedPaths)
				{
					string pattern = String.Format(@"{0}", s);
					MatchCollection tmpMatch = Regex.Matches(cmd.ToString(), pattern);
					if (tmpMatch.Count > 0)
					{
						whitelistedPath = true;
					}
				}
				if (whitelistedPath)
				{
					break;
				}

				if (debug)
				{
					WriteLog(String.Format("Checking - {0}({1})", procName, pid));
				}

				//Checking Process
				if (spc[0] == '1'){
					spr = suspiciousProcessFunc(procName.ToString(), name.ToString());
				}
				else
				{
					spr = false;
				}
				if (debug)
				{
					WriteLog(String.Format("SuspProc: {0}", spr));
				}
				if (spc[3] == '1' && spr)
				{
					WriteLog(String.Format("SuspiciousProcess - {0}({1})", procName, pid));
				}
				if(spr){
					react(pid, cmd, procName, mhc, mhr, mdsc, mdsr, sepc, sepr, dec, der, spc, spr, sppc, sppr, obfusc, obfusr);
					return;
				}

				//Checking ParentPRocess
				if (sppc[0] == '1')
				{
					sppr = suspiciousParentProcessFunc((uint)ppid);
				}
				else
				{
					sppr = false;
				}
				if (debug)
				{
					WriteLog(String.Format("SuspParentProc: {0}", sppr));
				}
				if (sppc[3] == '1' && sppr){
					WriteLog(String.Format("SuspiciousProcess - {0}({1}) - started from - ({2})", procName, pid, ppid));
				}
				if(sppr){
					react(pid, cmd, procName, mhc, mhr, mdsc, mdsr, sepc, sepr, dec, der, spc, spr, sppc, sppr, obfusc, obfusr);
					return;
				}

				//Checking ExecutableHash
				if (mhc[0] == '1')
				{
					mhr = maliciousHashFunc(exePath.ToString());
				}
				else
				{
					mhr = false;
				}
				if (debug)
				{
					WriteLog(String.Format("MalHash: {0}", mhr));
				}
				if (mhc[3] == '1' && mhr){
					WriteLog(String.Format("Signature found! - MALWARE! - {0}", exePath));
				}
				if(mhr){
					react(pid, cmd, procName, mhc, mhr, mdsc, mdsr, sepc, sepr, dec, der, spc, spr, sppc, sppr, obfusc, obfusr);
					return;
				}

				//Checking dynamicSignature
				if (mdsc[0] == '1')
				{
					mdsr = dynamicSignatureFunc(cmd.ToString());
				}
				else
				{
					mdsr = false;
				}
				if (debug)
				{
					WriteLog(String.Format("malDynSig: {0}",mdsr));
				}
				if (mdsc[3] == '1' && mdsr){
					WriteLog(String.Format("Dynamic Signature found! - MALWARE! - {0}", cmd));
				}
				if(mdsr){
					react(pid, cmd, procName, mhc, mhr, mdsc, mdsr, sepc, sepr, dec, der, spc, spr, sppc, sppr, obfusc, obfusr);
					return;
				}

				//Checking cmdLine
				if (obfusc[0] == '1')
				{
					obfusr = checkObfuscationFunc(cmd.ToString());
				}
				else
				{
					obfusr = false;
				}
				if (debug)
				{
					WriteLog(String.Format("obfuscation: {0}", obfusr));
				}
				if (obfusc[3] == '1' && obfusr){
					WriteLog("Obfuscated cmdLine");
				}
				if(obfusr){
					react(pid, cmd, procName, mhc, mhr, mdsc, mdsr, sepc, sepr, dec, der, spc, spr, sppc, sppr, obfusc, obfusr);
					return;
				}

				//Checking ExecutablePath
				if (sepc[0] == '1')
				{
					sepr = suspiciousExePathFunc(cmd.ToString());
				}
				else
				{
					sepr = false;
				}
				if (debug)
				{
					WriteLog(String.Format("SuspExePath: {0}", sepr));
				}
				if (sepc[3] == '1' && sepr){
					WriteLog(String.Format("SuspiciousExecutionPath - {0}({1}) - {2}", procName, pid, cmd));
				}
				if(sepr){
					react(pid, cmd, procName, mhc, mhr, mdsc, mdsr, sepc, sepr, dec, der, spc, spr, sppc, sppr, obfusc, obfusr);
					return;
				}

				//Checking Extension
				if (dec[0] == '1')
				{
					der = doubleExtFunc(cmd.ToString());
				}
				else
				{
					der = "false";
				}
				if (debug)
				{
					WriteLog(String.Format("doubleExt: {0}", der));
				}
				if (dec[3] == '1' && der != "false"){
					WriteLog(String.Format("DoubleExtension - {0}({1}) - {2}", procName, pid, der));
				}
				if(der != "false"){
					react(pid, cmd, procName, mhc, mhr, mdsc, mdsr, sepc, sepr, dec, der, spc, spr, sppc, sppr, obfusc, obfusr);
					return;
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
				object cmd = tmp.Properties["CommandLine"].Value;

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
					string userReturn = ask((uint)pid, procName.ToString(), 2);
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
			WriteLog(ppid.ToString());
			try{
				WqlObjectQuery parentQuery = new WqlObjectQuery(String.Format("SELECT * FROM Win32_Process WHERE ProcessId={0}", ppid));
				ManagementObjectSearcher searcherParent = new ManagementObjectSearcher(parentQuery);
				ManagementObjectCollection collectionParent = searcherParent.Get();
				string parentProcName = "";
				string ppName = "";
				foreach (ManagementObject tmpParent in collectionParent)
				{
					parentProcName = tmpParent.Properties["Caption"].Value.ToString();
					ppName = tmpParent.Properties["Name"].Value.ToString();
					WriteLog(parentProcName);
					if (suspiciousParents.Contains(parentProcName) || suspiciousParents.Contains(ppName))
					{
						return true;
					}
				}
				return false;
			}
			catch (Exception e){
				WriteLog(String.Format("Exception: {0}", e.Message));
				return false;
			}
		}

		//Checking for a known malware signature
		private bool maliciousHashFunc(string exePath)
		{
			string suspMD5 = CalculateMD5(exePath);
			if (suspMD5 == "false"){
				return false;
			}
			if (sig.Contains(suspMD5))
			{
				return true;
			}
			return false;
		}

		private bool dynamicSignatureFunc(string cmd)
		{
			string PathPattern = @"[A-Z]\:\\[\w(?\\)]*.\w*(\.\w*)?";
			MatchCollection cmdFiles = Regex.Matches(cmd, PathPattern);
			foreach (var file in cmdFiles){
				//Only check if file is in suspicious Path, because this is very resource intensive
				if (suspiciousExePathFunc(file.ToString()))
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
			if (File.Exists(filename))
			{
				var md5 = MD5.Create();
				try{
					var stream = File.OpenRead(filename);
					var hash = md5.ComputeHash(stream);
					return BitConverter.ToString(hash).Replace("-", "").ToLower();
				}
				catch (Exception e){
					WriteLog(String.Format("Exception: {0}", e.Message));
					return "false";
				}
			}
			else{
				return "false";
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

		private bool obfuscationLimiter(string cmd)
		{
			if ((Regex.Matches(cmd,@"cmd\.exe").Count > 0) || (Regex.Matches(cmd,@"powershell\.exe").Count > 0)){
				return true;
			}
			return false;
		}

		private bool checkObfuscationFunc(string cmd)
		{
			if (cmd.Length >= 100 && obfuscationLimiter(cmd)){
				return true;
			}
			return false;
		}

		private void react(object pid, object cmd, object procName, char[] mhc, bool mhr, char[] mdsc, bool mdsr, char[] sepc, bool sepr, char[] dec, string der, char[] spc, bool spr, char[] sppc, bool sppr, char[] obfusc, bool obfusr){
			if (gui)
			{
				if ((mhc[1] == '1' && mhr) || (mdsc[1] == '1' && mdsr) || (sepc[1] == '1' && sepr) || (dec[1] == '1' && der != "false") || (spc[1] == '1' && spr) || (sppc[1] == '1' && sppr) || (obfusc[1] == '1' && obfusr)){
					KillProc((uint)pid);
				}
				else if ((mhc[1] == '4' && mhr) || (mdsc[1] == '4' && mdsr) || (sepc[1] == '4' && sepr) || (dec[1] == '4' && der != "false") || (spc[1] == '4' && spr) || (sppc[1] == '4' && sppr) || (obfusc[1] == '4' && obfusr)){
					gui = false;
					int i = 0;
					if ( mhr || mdsr || spr || sppr || obfusr ){
						i = 1;
					}else if ( sepr || der != "false" ){
						i = 3;
					}
					string userReturn = ask((uint)pid, cmd.ToString(), i);
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
					if (gui == false && guiAtStartUp == true)
					{
						gui = true;
					}
				}
				else if ((mhc[1] == '2' && mhr) || (mdsc[1] == '2' && mdsr) || (sepc[1] == '2' && sepr) || (dec[1] == '2' && der != "false") || (spc[1] == '2' && spr) || (sppc[1] == '2' && sppr) || (obfusc[1] == '2' && obfusr)){
					SuspendProc((uint)pid);
				}
			}
			else
			{
				if ((mhc[2] == '1' && mhr) || (mdsc[2] == '1' && mdsr) || (sepc[2] == '1' && sepr) || (dec[2] == '1' && der != "false") || (spc[2] == '1' && spr) || (sppc[2] == '1' && sppr) || (obfusc[2] == '1' && obfusr)){
					KillProc((uint)pid);
				}
				else if ((mhc[2] == '2' && mhr) || (mdsc[2] == '2' && mdsr) || (sepc[2] == '2' && sepr) || (dec[2] == '2' && der != "false") || (spc[2] == '2' && spr) || (sppc[2] == '2' && sppr) || (obfusc[2] == '2' && obfusr)){
					SuspendProc((uint)pid);
				}
			}
		}

		private string ask(uint pid, string exePath, int lvl){
			SuspendProc(pid);
			sendMsg(exePath, lvl);
			Message userRet = rcvMsg();
			return userRet.Label.ToString();
		}

		private void sendMsg(string lbl, int lvl)
		{
			Message message = new Message();
			string lvllbl = lvl.ToString() + lbl;
			message.Label = lvllbl;
			try
			{
				WriteLog(message.Label.ToString());
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

		private void checkForGui(object source, ElapsedEventArgs e)
		{
			var guiProc = Process.GetProcessesByName("ProcessBouncerGUI");
			if (guiProc.Length <= 0){
				gui = false;
				guiAtStartUp = false;
			}
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
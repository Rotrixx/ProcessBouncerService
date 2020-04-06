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
		int logLevel;

		string[] sig;

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
			
			/*
			if(MessageQueue.Exists(@".\private$\ProcessBouncerQueue"))
			{
				pbq = new MessageQueue(@".\private$\ProcessBouncerQueue");
			}
			else
			{
				pbq = MessageQueue.Create(@".\private$\ProcessBouncerQueue");
			}
			*/

			//Reading Signatures
			sig = System.IO.File.ReadAllLines(@"C:\ProcessBouncer\sig");

			//Reading ConfigFile
			int counter = 1;
			string[] lines = System.IO.File.ReadAllLines(@"C:\ProcessBouncer\config.txt");
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
						intervalBulk = Convert.ToInt32(line);
						break;
					case 11:
						logLevel = Convert.ToInt32(line);
						break;
				}
				counter++;
			}


			WriteLog("Service has been started");
			//Watch for newly started Processes
			ManagementEventWatcher eventWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
			eventWatcher.EventArrived += new EventArrivedEventHandler(CheckProcess);
			eventWatcher.Start();

			//Check for bilk writing with a timer
			timerBulk.Elapsed += new ElapsedEventHandler(CheckTransferProcess);
			timerBulk.Interval = intervalBulk;
			timerBulk.Enabled = true;
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
				string parentProcName = "";

				bool suspExePath = false;
				bool suspExt = false;
				bool whitelistedScript = false;

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

				if (logLevel >= 4)
				{
					WriteLog(String.Format("Checking - {0}({1})", procName, pid));
				}

				// Suspend newly created Process till it was checked
				//Problems at startup?
				//SuspendProc((uint)pid);

				//Check for suspicous Path
				foreach (string s in suspiciousExePath)
				{
					string pattern = String.Format(@"{0}", s);
					MatchCollection tmpMatch = Regex.Matches(cmd.ToString(), pattern);
					if (tmpMatch.Count > 0)
					{
						suspExePath = true;
						if (logLevel >= 3)
						{
							WriteLog(String.Format("SuspiciousExecutionPath - {0}({1}) - {2}", procName, pid, cmd));
						}
					}
				}

				//Check for double Extensions
				string doubleExtPattern = @"\\[A-Za-z0-9]*\.[A-Za-z0-9]*\.[A-Za-z0-9]*(?!\.)\b";
				//May have problems with some Windows directories
				foreach(Match match in Regex.Matches(cmd.ToString(),doubleExtPattern))
				{
					suspExt = true;
					if (logLevel >= 3)
					{
						WriteLog(String.Format("DoubleExtension - {0}({1}) - {2}", procName, pid, match));
					}
				}

				//Check Hash of exe file
				//var watch = System.Diagnostics.Stopwatch.StartNew();
				string suspMD5 = CalculateMD5(exePath.ToString());
				if (sig.Contains(suspMD5))
				{
					WriteLog(String.Format("Signature found! - MALWARE! - {0}", exePath));
					KillProc((uint)pid);
					return;
				}
				//watch.Stop();
				//var elapsedMs = watch.ElapsedMilliseconds;
				//if(logLevel >= 5) WriteLog(String.Format("Checked {0} Hashes in {1} Milliseconds", sig.Length, elapsedMs));

				//Check for blacklisted/suspicous Processes by name
				if (suspicious.Contains(procName) || suspicious.Contains(name))
				{
					bool suspParent = false;
					WqlObjectQuery parentQuery = new WqlObjectQuery(String.Format("SELECT Caption FROM Win32_Process WHERE ProcessId={0}", ppid));
					ManagementObjectSearcher searcherParent = new ManagementObjectSearcher(parentQuery);
					ManagementObjectCollection collectionParent = searcherParent.Get();
					foreach (ManagementObject tmpParent in collectionParent)
					{
						parentProcName = tmpParent.Properties["Caption"].ToString();
						if (suspiciousParents.Contains(parentProcName))
						{
							suspParent = true;
						}
					}
					if (suspParent)
					{
						//ToDo
						//Add recursion for indirect parents
						WriteLog(String.Format("SuspiciousProcess - {0}({2}) - started from - {1}({3})", procName, parentProcName, pid, ppid));
						if (logLevel >= 3)
						{
							WriteLog(String.Format("KillingProcess - {0}", pid));
						}
						KillProc((uint)pid);
						KillProc((uint)ppid);
						return;
					}

					WriteLog(String.Format("SuspiciousProcessStarted - {0}({1})", procName, pid));
					if (logLevel >= 3)
					{
						WriteLog(String.Format("KillingProcess - {0}", pid));
					}
					KillProc((uint)pid);
					return;
				}

				/*
				if(suspExePath || suspExt){
					sendMsg(exePath.ToString(), "Susp");
					Message userRet = rcvMsg();
					if(userRet.Body.ToString() == "R" && userRet.Label.ToString() == "Susp")
					{
						WriteLog(String.Format("User resumed {0}({1})", procName, pid));
						ResumeProc((uint)pid);
						return;
					}
					else if(userRet.Body.ToString() == "K" && userRet.Label.ToString() == "Susp")
					{
						WriteLog(String.Format("User killed {0}({1})", procName, pid));
						KillProc((uint)pid);
						return;
					}
					else if(userRet.Body.ToString() == "S" && userRet.Label.ToString() == "Susp")
					{
						WriteLog(String.Format("User keeps suspending {0}({1})", procName, pid));
						KillProc((uint)pid);
						return;
					}
					else
					{
						WriteLog("No Time!");
					}
				}
				*/

				if (logLevel >= 5)
				{
					WriteLog(String.Format("All Good! - {0}({1})", procName, pid));
				}

				// Resume Process if Process is not malicous
				//ResumeProc((uint)pid);
			}
			return;
		}

		private void CheckTransferProcess(object source, ElapsedEventArgs e)
		{
			if (logLevel >= 5)
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
				//SuspendProc((uint)pid);
				WriteLog(String.Format("{0}({1}) does bulk writing", procName, pid));
				/*
				sendMsg(String.Format("{0}", exePath),"Bulk");
				Message userRet = rcvMsg();
				if(userRet.Body.ToString() == "R" && userRet.Body.ToString() == "Bulk")
				{
					WriteLog(String.Format("User resumed {0}({1})", procName, pid));
					ResumeProc((uint)pid);
					return;
				}
				else if(userRet.Body.ToString() == "K" && userRet.Body.ToString() == "Bulk")
				{
					WriteLog(String.Format("User killed {0}({1})", procName, pid));
					KillProc((uint)pid);
					return;
				}
				else if(userRet.Body.ToString() == "S" && userRet.Body.ToString() == "Bulk")
				{
					WriteLog(String.Format("User keeps suspending {0}({1})", procName, pid));
					KillProc((uint)pid);
					return;
				}
				else
				{
					WriteLog("No Time!");
				}
				//KillProc((uint)pid);
				*/
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

		private void sendMsg(string msg, string lbl)
		{
			Message message = new Message();
			message.Body = msg;
			message.Label = lbl;
			pbq.Send(message);
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
					if (logLevel >= 4)
					{
						WriteLog(String.Format("SuspendedProcess - {0}", procId));
					}
					return;
				}
				if (logLevel >= 2)
				{
					WriteLog(String.Format("Failed to suspend Process - {0}", procId));
				}
				return;
			}
			if (logLevel >= 2)
			{
				WriteLog(String.Format("Unable to open Process - {0}", procId));
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
					if (logLevel >= 4)
					{
						WriteLog(String.Format("ResumedProcess - {0}", procId));
					}
					return;
				}
				if (logLevel >= 2)
				{
					WriteLog(String.Format("Failed to resume Process - {0}", procId));
				}
				return;
			}
			if (logLevel >= 2)
			{
				WriteLog(String.Format("Unable to open Process - {0}", procId));
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
				if (logLevel >= 2)
				{
					WriteLog(String.Format("Failed to kill Process - {0}", procId));
				}
				return;
			}
			if (logLevel >= 2)
			{
				WriteLog(String.Format("Unable to open Process - {0}", procId));
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
	}
}
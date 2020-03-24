using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.IO;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;

namespace ProcessBouncerService
{
    public partial class Service1 : ServiceBase
    {
        string logPath = "C:\\ProcessBouncer";
		string [] suspicious = {
			"powershell.exe","cmd.exe","regedit.exe","cmd","powershell",
			"msiexec.exe","certutil.exe","bitadmin.exe","psexec.exe","winexesvc","remcos.exe","wscript.exe","cscript.exe","reg.exe","sc.exe","netsh","whoami", "copy", "net", "tasklist","schtasks","streams.exe" // lotl Tools
		};
		string [] suspiciousParents = {"WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","powershell.exe","cmd.exe","WINWORD","EXCEL","POWERPNT","cmd","powershell"};
		string [] suspiciousExePath = {"C:\\Users"};
		string [] ext1 = { 
			"jpg", "jpeg", "png", "pdf", 
			"doc", "docx", "docm", "dot", "dotm", 
			"xls", "xlsm", "xltm", "xlsx", "xlsb", "xlam", 
			"ppt", "pot", "pptx", "pptm", "potm", "ppam", "ppsm", "sldm" 
		};
		string [] ext2 = {"exe", "com", "ps1", "dll", "bat", "pif"};
		List<string> doubleExt = new List<string>();

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

			WriteLog("Service has been started");
			//WqlEventQuery eventQuery = new WqlEventQuery("__InstanceCreationEvent", new TimeSpan(0,0,1), "TargetInstance isa \"Win32_Process\"");
			ManagementEventWatcher eventWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
			eventWatcher.EventArrived += new EventArrivedEventHandler(CheckProcess);
			eventWatcher.Start();
        }

        private void CheckProcess(object sender, EventArrivedEventArgs e)
        {
            //ToDo
			object procName = e.NewEvent.Properties["ProcessName"].Value;
			int pid = (int)e.NewEvent.Properties["ProcessID"].Value;
			int ppid = (int)e.NewEvent.Properties["ParentProcessID"].Value;
            Process proc = Process.GetProcessById(ppid);
			object parentProcName = proc.ProcessName;
			string exePath = Process.GetProcessById(pid).MainModule.FileName;

			bool suspExePath = false;
			bool suspExt = false;

			// Suspend newly created Process till it was checked
			SuspendProc((uint)pid);

			//if(suspiciousExePath.Contains(exePath) or doubleExt.Contains(Path.GetFileName(exePath)))
			// ToDo: Find better solution than substring
			if(suspiciousExePath.Contains(exePath.Substring(0,7)))
			{
				suspExePath = true;
				WriteLog(String.Format("SuspiciousExecutionPath - {0}({1})", procName, pid));
			}

			var splittedPath = Path.GetFileName(exePath).Split('.');
			if(splittedPath.Length > 2)
			{
				if(ext1.Contains(splittedPath[splittedPath.Length -1]) && ext2.Contains(splittedPath[splittedPath.Length -2]))
				{
					suspExt = true;
					WriteLog(String.Format("DoubleExtension - {0}", pid));
				}
			}

			if(suspicious.Contains(procName))
			{
                if(suspiciousParents.Contains(parentProcName))
				{
					//ToDo
					//Add recursion for indirect parents
            		WriteLog(String.Format("SuspiciousProcess - {0}({2}) - started from - {1}({3})", procName, parentProcName, pid, ppid));
					WriteLog(String.Format("KillingProcess - {0}", pid));
					KillProc((uint)pid);
					KillProc((uint)ppid);
					return;
				}
				WriteLog(String.Format("SuspiciousProcessStarted - {0} - {1}", procName, pid));
				WriteLog(String.Format("KillingProcess - {0}", pid));
				KillProc((uint)pid);
				return;
			}

			// Resume Process if Process is not malicous
			ResumeProc((uint)pid);
			//ToDo
			//RsumeWithSuperVision(look for unusualy high read/write operations / critical access tries)
        }

		private void SuspendProc(uint procId)
		{
            IntPtr maliciousProc = OpenProcess(ProcessAccess.SuspendResume, false, procId);
			if(maliciousProc != IntPtr.Zero)
			{
            	uint suspendProc = SuspendProcess(maliciousProc);
				if(suspendProc == 0)
				{
					CloseHandle(maliciousProc);
					WriteLog(String.Format("SuspendedProcess - {0}", procId));
					return;
				}
				WriteLog(String.Format("Failed to suspend Process - {0}", procId));
				return;
			}
			WriteLog(String.Format("Unable to open Process - {0}", procId));
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
				WriteLog(String.Format("Failed to resume Process - {0}", procId));
				return;
			}
			WriteLog(String.Format("Unable to open Process - {0}", procId));
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
				WriteLog(String.Format("Failed to kill Process - {0}", procId));
				return;
			}
			WriteLog(String.Format("Unable to open Process - {0}", procId));
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

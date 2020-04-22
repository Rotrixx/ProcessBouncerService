using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Messaging;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Forms;
using Message = System.Messaging.Message;
using static ProcessBouncerGUI.PupUp;
using System.Diagnostics;

namespace ProcessBouncerGUI
{
	public partial class Form1 : Form
	{
		MessageQueue pbq;
		MessagePriority highest = MessagePriority.Highest;
		MessagePriority high = MessagePriority.High;
		MessagePriority normal = MessagePriority.Normal;
		MessagePriority low = MessagePriority.Low;

		TimeSpan interval = new TimeSpan(0,0,1); //1 sec?

		public Form1()
		{
			InitializeComponent();
			if(MessageQueue.Exists(@".\private$\pbq"))
			{
				pbq = new MessageQueue(@".\private$\pbq");
			}
			else
			{
				pbq = MessageQueue.Create(@".\private$\pbq");
			}

			pbq.ReceiveCompleted += new ReceiveCompletedEventHandler(QueueMessageReceived);
			pbq.BeginReceive();
		}

		/*
		while (true)
		{
			Message curr = rcvMsg(interval);
			if(curr.Label.ToString() == "Susp")
			{
				PupUp tmp = new PupUp();
				tmp.Show();
				Message response = rcvMsg(new TimeSpan(0, 1, 0));
				if (response.Body.ToString() == "Done")
				{
					tmp.Close();
				}
			}
			else if(curr.Label.ToString() == "Bulk")
			{
				PupUp tmp = new PupUp();
				tmp.Show();
				Message response = rcvMsg(new TimeSpan(0,1,0));
				if (response.Body.ToString() == "Done")
				{
					tmp.Close();
				}
			}
		}
		*/

		private void buttonAddProc_Click(object sender, EventArgs e)
		{
			
		}

		private void blockedProcesses_Click(object sender, EventArgs e)
		{

		}

		private void buttonEditConfig_Click(object sender, EventArgs e)
		{
			DecryptFile("C:\\ProcessBouncer\\safeConfig.txt","C:\\ProcessBouncer\\tmp.txt");
			Process editor = Process.Start("C:\\ProcessBouncer\\tmp.txt");
			editor.WaitForExit();
			EncryptFile("C:\\ProcessBouncer\\tmp.txt","C:\\ProcessBouncer\\safeConfig.txt");
			File.Delete("C:\\ProcessBouncer\\tmp.txt");
		}

		private void buttonTogglePopUp_Click(object sender, EventArgs e)
		{
			EncryptFile("C:\\ProcessBouncer\\config.txt","C:\\ProcessBouncer\\safeConfig.txt");
		}

		private void blockedProcesses_SelectedIndexChanged(object sender, EventArgs e)
		{

		}

		public void sendMsg(string lbl)
		{
			Message message = new Message();
			message.Label = lbl;
			pbq.Send(message);
			return;
		}

		private Message rcvMsg(TimeSpan interval)
		{
			//pbq.MessageReadPropertyFilter.Priority = true;
			//pbq.Formatter = new XmlMessageFormatter(new Type[] {typeof(string)});
			try
			{
				Message message = pbq.Receive(interval);
				return message;
			}
			catch (MessageQueueException e)
			{
				Console.WriteLine(e.Message);
				Console.WriteLine(e.ErrorCode);
				Console.WriteLine(e.MessageQueueErrorCode);
			}
			catch (InvalidOperationException e)
			{
				
			}
			Message empty = new Message();
			return empty;
		}

		private void EncryptFile(string inputFile, string outputFile)
		{
			try
			{
				byte[] data = File.ReadAllBytes(inputFile);
				byte[] encryptedBytes = null;

				byte[] passBytes = Encoding.ASCII.GetBytes("b1bHhco64JQ14Pg4");
				byte[] saltBytes = Encoding.ASCII.GetBytes("xCZmKg7Kv1xpFUEdlgpXaSvJ186RvB");

				var key = new Rfc2898DeriveBytes(passBytes, saltBytes, 32768);
				// create an AES object
				using (Aes aes = new AesManaged())
				{
					// set the key size to 256
					aes.KeySize = 256;
					aes.Key = key.GetBytes(aes.KeySize / 8);
					aes.IV = key.GetBytes(aes.BlockSize / 8);
					using (MemoryStream ms = new MemoryStream())
					{
						using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
						{
							cs.Write(data, 0, data.Length);
							cs.Close();
						}
						encryptedBytes = ms.ToArray();
					}
				}
				using (var fs = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
				{
					fs.Write(encryptedBytes, 0, encryptedBytes.Length);
				}
			}
			catch (Exception e)
			{
				MessageBox.Show("Encryption failed!", "Error");
				Console.WriteLine(e.Message);
			}
		}

		private void DecryptFile(string inputFile, string outputFile)
		{
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
				using (var fs = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
				{
					fs.Write(dencryptedBytes, 0, dencryptedBytes.Length);
				}
			}
		}

		private void QueueMessageReceived(Object source, ReceiveCompletedEventArgs asyncResult)
		{
			MessageQueue mq = (MessageQueue)source;

			//once a message is received, stop receiving
			Message curr = mq.EndReceive(asyncResult.AsyncResult);

			PupUp temp = new PupUp();
			temp.LblText = curr.Label.ToString();
			DialogResult result =  temp.ShowDialog();

			if (result == DialogResult.Yes)
			{
				sendMsg("R");
			}
			else if (result == DialogResult.No)
			{
				sendMsg("K");
			}
			else if (result == DialogResult.Ignore)
			{
				sendMsg("S");
			}
			temp.Dispose();

			//begin receiving again
			mq.BeginReceive();
			return;
		}

	}
}

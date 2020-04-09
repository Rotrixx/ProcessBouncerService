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
			PupUp temp = new PupUp();
			temp.Show();
		}

		private void buttonTogglePopUp_Click(object sender, EventArgs e)
		{

		}

		private void openConfigFile()
		{
			
		}

		private void blockedProcesses_SelectedIndexChanged(object sender, EventArgs e)
		{

		}

		public void sendMsg(string msg, string lbl)
		{
			Message message = new Message();
			message.Body = msg;
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

		//Source: https://www.codeproject.com/articles/26085/file-encryption-and-decryption-in-c
		private void EncryptFile(string inputFile, string outputFile)
		{
			try
			{
				string password = @"8e4wttmVgeMPmjd_Zdf#NJ-!Q"; // Your Key Here
				UnicodeEncoding UE = new UnicodeEncoding();
				byte[] key = UE.GetBytes(password);

				string cryptFile = outputFile;
				FileStream fsCrypt = new FileStream(cryptFile, FileMode.Create);

				RijndaelManaged RMCrypto = new RijndaelManaged();

				CryptoStream cs = new CryptoStream(fsCrypt, RMCrypto.CreateEncryptor(key, key), CryptoStreamMode.Write);

				FileStream fsIn = new FileStream(inputFile, FileMode.Open);

				int data;
				while ((data = fsIn.ReadByte()) != -1)
				{
					cs.WriteByte((byte)data);
				}

				fsIn.Close();
				cs.Close();
				fsCrypt.Close();
			}
			catch
			{
				MessageBox.Show("Encryption failed!", "Error");
			}
		}

		//Source: https://www.codeproject.com/articles/26085/file-encryption-and-decryption-in-c
		private void DecryptFile(string inputFile, string outputFile)
		{
			{
				string password = @"8e4wttmVgeMPmjd_Zdf#NJ-!Q"; // Your Key Here

				UnicodeEncoding UE = new UnicodeEncoding();
				byte[] key = UE.GetBytes(password);

				FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);

				RijndaelManaged RMCrypto = new RijndaelManaged();

				CryptoStream cs = new CryptoStream(fsCrypt, RMCrypto.CreateDecryptor(key, key), CryptoStreamMode.Read);

				FileStream fsOut = new FileStream(outputFile, FileMode.Create);

				int data;
				while ((data = cs.ReadByte()) != -1)
				{
					fsOut.WriteByte((byte)data);
				}

				fsOut.Close();
				cs.Close();
				fsCrypt.Close();
			}
		}

		private void QueueMessageReceived(Object source, ReceiveCompletedEventArgs asyncResult)
		{
			MessageQueue mq = (MessageQueue)source;

			//once a message is received, stop receiving
			Message curr = mq.EndReceive(asyncResult.AsyncResult);

			//popUpFunc(curr);
			PupUp temp = new PupUp
			{
				LblText = curr.Body.ToString()
			};
			temp.ShowDialog();

			//do something with the message
			/*
			if (curr.Label.ToString() == "Susp")
			{
				PupUp temp = new PupUp();
				temp.Show();
				msQueue.BeginReceive();
				Message response = msQueue.EndReceive();
				if (response.Body.ToString() == "Done")
				{
					tmp.Close();
				}
			}
			else if (curr.Label.ToString() == "Bulk")
			{
				tmp.Show();
				/*msQueue.BeginReceive();
				response = msQueue.EndReceive();
				if (response.Body.ToString() == "Done")
				{
					tmp.Close();
				}
			}
			*/


			//begin receiving again
			//mq.BeginReceive();
			return;
		}

	}
}

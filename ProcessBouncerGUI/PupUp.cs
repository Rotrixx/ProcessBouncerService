﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Messaging;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ProcessBouncerGUI
{
	public partial class PupUp : Form
	{
		MessageQueue pbq;
		public PupUp()
		{
			InitializeComponent();
			
			MessageQueue pbq = new MessageQueue(@".\private$\ProcessBouncerQueue");
		}

		public string LblText
		{
			get
			{
				return this.labelDynamic.Text;
			}
			set
			{
				this.labelDynamic.Text = value;
			}
		}

		private void buttonKill_Click(object sender, EventArgs e)
		{
			sendMsg("K", "Susp");
		}

		private void buttonSuspend_Click(object sender, EventArgs e)
		{
			sendMsg("S", "Susp");
		}

		private void buttonResume_Click(object sender, EventArgs e)
		{
			sendMsg("R", "Susp");
		}

		public void sendMsg(string msg, string lbl)
		{
			System.Messaging.Message message = new System.Messaging.Message();
			message.Body = msg;
			message.Label = lbl;
			pbq.Send(message);
			return;
		}
	}
}

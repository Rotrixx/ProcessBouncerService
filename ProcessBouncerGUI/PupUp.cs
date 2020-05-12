using System;
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
		public PupUp()
		{
			InitializeComponent();
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

		public string MsgText
		{
			get
			{
				return this.labelStatic.Text;
			}
			set
			{
				this.labelStatic.Text = value;
			}
		}
	}
}

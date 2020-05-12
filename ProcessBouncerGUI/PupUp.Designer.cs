namespace ProcessBouncerGUI
{
    partial class PupUp
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(PupUp));
            this.buttonKill = new System.Windows.Forms.Button();
            this.buttonResume = new System.Windows.Forms.Button();
            this.buttonSuspend = new System.Windows.Forms.Button();
            this.labelStatic = new System.Windows.Forms.Label();
            this.labelDynamic = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // buttonKill
            // 
            this.buttonKill.DialogResult = System.Windows.Forms.DialogResult.No;
            this.buttonKill.Location = new System.Drawing.Point(287, 126);
            this.buttonKill.Name = "buttonKill";
            this.buttonKill.Size = new System.Drawing.Size(75, 23);
            this.buttonKill.TabIndex = 0;
            this.buttonKill.Text = "Kill";
            this.buttonKill.UseVisualStyleBackColor = true;
            // 
            // buttonResume
            // 
            this.buttonResume.DialogResult = System.Windows.Forms.DialogResult.Yes;
            this.buttonResume.Location = new System.Drawing.Point(45, 126);
            this.buttonResume.Name = "buttonResume";
            this.buttonResume.Size = new System.Drawing.Size(75, 23);
            this.buttonResume.TabIndex = 1;
            this.buttonResume.Text = "Resume";
            this.buttonResume.UseVisualStyleBackColor = true;
            // 
            // buttonSuspend
            // 
            this.buttonSuspend.DialogResult = System.Windows.Forms.DialogResult.Ignore;
            this.buttonSuspend.Location = new System.Drawing.Point(168, 126);
            this.buttonSuspend.Name = "buttonSuspend";
            this.buttonSuspend.Size = new System.Drawing.Size(75, 23);
            this.buttonSuspend.TabIndex = 2;
            this.buttonSuspend.Text = "Suspend";
            this.buttonSuspend.UseVisualStyleBackColor = true;
            // 
            // labelStatic
            // 
            this.labelStatic.AutoSize = true;
            this.labelStatic.Location = new System.Drawing.Point(17, 80);
            this.labelStatic.Name = "labelStatic";
            this.labelStatic.Size = new System.Drawing.Size(367, 26);
            this.labelStatic.TabIndex = 3;
            this.labelStatic.Text = "ccccccccccddddddddddccccccccccddddddddddccccccccccdddddddddd\r\nccccccccccddddddddd" +
    "dccccccccccddddddddddccccccccccdddddddddd";
            this.labelStatic.TextAlign = System.Drawing.ContentAlignment.TopCenter;
            // 
            // labelDynamic
            // 
            this.labelDynamic.AutoSize = true;
            this.labelDynamic.Location = new System.Drawing.Point(12, 9);
            this.labelDynamic.Name = "labelDynamic";
            this.labelDynamic.Size = new System.Drawing.Size(367, 52);
            this.labelDynamic.TabIndex = 4;
            this.labelDynamic.Text = resources.GetString("labelDynamic.Text");
            // 
            // PupUp
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(408, 189);
            this.Controls.Add(this.labelDynamic);
            this.Controls.Add(this.labelStatic);
            this.Controls.Add(this.buttonSuspend);
            this.Controls.Add(this.buttonResume);
            this.Controls.Add(this.buttonKill);
            this.Name = "PupUp";
            this.Text = "ProcessBouncerService - PopUp";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button buttonKill;
        private System.Windows.Forms.Button buttonResume;
        private System.Windows.Forms.Button buttonSuspend;
        private System.Windows.Forms.Label labelStatic;
        private System.Windows.Forms.Label labelDynamic;
    }
}
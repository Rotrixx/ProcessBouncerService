namespace ProcessBouncerGUI
{
    partial class Form1
    {
        /// <summary>
        /// Erforderliche Designervariable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Verwendete Ressourcen bereinigen.
        /// </summary>
        /// <param name="disposing">True, wenn verwaltete Ressourcen gelöscht werden sollen; andernfalls False.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Vom Windows Form-Designer generierter Code

        /// <summary>
        /// Erforderliche Methode für die Designerunterstützung.
        /// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
        /// </summary>
        private void InitializeComponent()
        {
            this.configTab = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.buttonEditConfig = new System.Windows.Forms.Button();
            this.buttonTogglePopUp = new System.Windows.Forms.Button();
            this.blockedProcesses = new System.Windows.Forms.ListBox();
            this.buttonAddProc = new System.Windows.Forms.Button();
            this.configTab.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.SuspendLayout();
            // 
            // configTab
            // 
            this.configTab.Controls.Add(this.tabPage1);
            this.configTab.Controls.Add(this.tabPage2);
            this.configTab.Location = new System.Drawing.Point(12, 12);
            this.configTab.Name = "configTab";
            this.configTab.SelectedIndex = 0;
            this.configTab.Size = new System.Drawing.Size(776, 426);
            this.configTab.TabIndex = 0;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.buttonTogglePopUp);
            this.tabPage1.Controls.Add(this.buttonEditConfig);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(768, 400);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Config";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.buttonAddProc);
            this.tabPage2.Controls.Add(this.blockedProcesses);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(768, 400);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Log";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // buttonEditConfig
            // 
            this.buttonEditConfig.Location = new System.Drawing.Point(356, 115);
            this.buttonEditConfig.Name = "buttonEditConfig";
            this.buttonEditConfig.Size = new System.Drawing.Size(100, 23);
            this.buttonEditConfig.TabIndex = 0;
            this.buttonEditConfig.Text = "Edit Config";
            this.buttonEditConfig.UseVisualStyleBackColor = true;
            this.buttonEditConfig.Click += new System.EventHandler(this.buttonEditConfig_Click);
            // 
            // buttonTogglePopUp
            // 
            this.buttonTogglePopUp.Location = new System.Drawing.Point(356, 192);
            this.buttonTogglePopUp.Name = "buttonTogglePopUp";
            this.buttonTogglePopUp.Size = new System.Drawing.Size(100, 23);
            this.buttonTogglePopUp.TabIndex = 1;
            this.buttonTogglePopUp.Text = "Toggle PupUp";
            this.buttonTogglePopUp.UseVisualStyleBackColor = true;
            this.buttonTogglePopUp.Click += new System.EventHandler(this.buttonTogglePopUp_Click);
            // 
            // blockedProcesses
            // 
            this.blockedProcesses.FormattingEnabled = true;
            this.blockedProcesses.Location = new System.Drawing.Point(6, 6);
            this.blockedProcesses.Name = "blockedProcesses";
            this.blockedProcesses.Size = new System.Drawing.Size(756, 329);
            this.blockedProcesses.TabIndex = 1;
            this.blockedProcesses.Click += new System.EventHandler(this.blockedProcesses_Click);
            this.blockedProcesses.SelectedIndexChanged += new System.EventHandler(this.blockedProcesses_SelectedIndexChanged);
            // 
            // buttonAddProc
            // 
            this.buttonAddProc.Location = new System.Drawing.Point(669, 341);
            this.buttonAddProc.Name = "buttonAddProc";
            this.buttonAddProc.Size = new System.Drawing.Size(93, 23);
            this.buttonAddProc.TabIndex = 2;
            this.buttonAddProc.Text = "Add to Whitelist";
            this.buttonAddProc.UseVisualStyleBackColor = true;
            this.buttonAddProc.Click += new System.EventHandler(this.buttonAddProc_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.configTab);
            this.Name = "Form1";
            this.Text = "ProcessBouncer";
            this.configTab.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage2.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TabControl configTab;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.Button buttonTogglePopUp;
        private System.Windows.Forms.Button buttonEditConfig;
        private System.Windows.Forms.Button buttonAddProc;
        private System.Windows.Forms.ListBox blockedProcesses;
    }
}


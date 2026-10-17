using System;
using System.Drawing;
using System.Windows.Forms;

namespace GuestBroker
{
    internal static class RegistrationDialog
    {
        internal static Target Choose()
        {
            // Registration is deliberately human-operated. No CLI/IPC path or name
            // can add a VM; no discovery scan or "register all" exists.
            using (var form = new Form())
            using (var name = new TextBox())
            using (var path = new TextBox())
            using (var browse = new Button())
            using (var accept = new Button())
            using (var cancel = new Button())
            {
                form.Text = "VMware Guest Broker - register one approved VM";
                form.ClientSize = new Size(700, 210);
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false; form.MinimizeBox = false;
                form.StartPosition = FormStartPosition.CenterScreen;
                var instruction = new Label { Text = "Register ONE VM you approve. No credentials are requested here; no VM is modified.", Left = 16, Top = 16, Width = 670 };
                var nameLabel = new Label { Text = "Unique name (letters, digits, _ or -; starts with a letter):", Left = 16, Top = 48, Width = 660 };
                name.SetBounds(16, 73, 660, 24); name.MaxLength = 48;
                path.SetBounds(16, 112, 545, 24); path.ReadOnly = true;
                browse.Text = "Choose VMX"; browse.SetBounds(570, 110, 108, 28);
                browse.Click += delegate
                {
                    using (var dialog = new OpenFileDialog())
                    {
                        dialog.Title = "Select the exact approved VMX (no other VM will be scanned)";
                        dialog.Filter = "VMware VMX (*.vmx)|*.vmx";
                        dialog.Multiselect = false;
                        dialog.CheckFileExists = true;
                        if (dialog.ShowDialog(form) == DialogResult.OK) path.Text = dialog.FileName;
                    }
                };
                accept.Text = "Review target"; accept.SetBounds(440, 166, 115, 28); accept.DialogResult = DialogResult.OK;
                cancel.Text = "Cancel"; cancel.SetBounds(566, 166, 112, 28); cancel.DialogResult = DialogResult.Cancel;
                form.Controls.AddRange(new Control[] { instruction, nameLabel, name, path, browse, accept, cancel });
                form.AcceptButton = accept; form.CancelButton = cancel;
                if (form.ShowDialog() != DialogResult.OK) throw new BrokerError("user_cancelled");
                Target target = VmIdentity.Capture(name.Text, path.Text);
                if (Native.MessageBoxW(IntPtr.Zero,
                    "Register ONLY this VM?\n\nName: " + target.Name + "\nVMX: " + target.Vmx + "\nVM UUID: " + target.Uuid +
                    "\nEnrollment file identity seed: " + target.FileIdentity + "\n\nNo credentials are stored by registration. Exact canonical path/UUID remains required; normal VMX rewrites do not rotate keys. Changed path/UUID is never silently adopted.",
                    "VMware Guest Broker: approve registration", 0x4 | 0x100 | 0x30 | 0x40000) != 6)
                    throw new BrokerError("user_cancelled");
                return target;
            }
        }
    }
}

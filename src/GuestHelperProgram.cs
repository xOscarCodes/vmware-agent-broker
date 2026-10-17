using System;
using System.Drawing;
using System.Windows.Forms;

namespace GuestBroker
{
    internal static class GuestHelperProgram
    {
        [STAThread]
        internal static int Main(string[] args)
        {
            Native.SetErrorMode(0x0001 | 0x0002 | 0x8000);
            try
            {
                if (args.Length == 0 || (args.Length == 1 && args[0] == "help"))
                {
                    Console.WriteLine("Broker guest fixture helper protocol 4 (Windows .NET Framework x86).\nManual guest-side enroll-root UI only; no password/credential input.\nQueries, new EMPTY creation, counts, same-parent owned rename, approved-name manifests.\nNEW separate owned-delete right: destroys entire helper-owned test objects INCLUDING test streams.\nOwned trees preflight all children; any foreign object refuses. No arbitrary recursive deletion or replacement.\nNo raw guest names/content output. Frozen pairs are separate; exact image/receipt still required.\nThis helper is NOT a sandbox against same-user/admin or a malicious guest."); return 0;
                }
                if (args.Length == 1 && args[0] == "enroll-root") return Enroll();
                if (args.Length == 1 && args[0] == "fixture-idle") { System.Threading.Thread.Sleep(35000); return 0; }
                if (args.Length == 3 && args[0] == "fixture-sink") return PublicFixtureSink.Run(args[1], args[2]);
                string self = FixtureProtocol.ImageHash(typeof(GuestHelperProgram).Assembly.Location);
                if (args.Length == 9 && args[0] == "supervise-fixture" && args[7] == "--owner-job")
                {
                    var store = new GuestRootStore(); GuestRootRecord root = store.Read(args[1], args[2]);
                    if (root.EnrollmentId != args[3] || root.ImageSha256 != self || args[4] != self) return FixtureProtocol.NotEnrolled;
                    return GuestProcessSupervisor.Run(store, root, args[5], args[6], GuestProcessSupervisor.LifetimeMilliseconds, args[8]);
                }
                return GuestProbe.Request(new GuestRootStore(), self, args);
            }
            catch (Exception) { return FixtureProtocol.IoFailure; } // No raw exception/path output.
        }
        private static int Enroll()
        {
            using (var form = new Form { Text = "Enroll ONE non-secret guest fixture root (protocol4)", ClientSize = new Size(740, 600), FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, StartPosition = FormStartPosition.CenterScreen })
            using (var target = new TextBox { Left = 16, Top = 92, Width = 700, MaxLength = 64 })
            using (var alias = new TextBox { Left = 16, Top = 150, Width = 300, MaxLength = 32 })
            using (var path = new TextBox { Left = 16, Top = 208, Width = 570, ReadOnly = true })
            using (var owned = new CheckBox { Left = 16, Top = 250, Width = 700, Text = "Explicitly permit NEW EMPTY fixture creation only (NO deletion, rename or overwrite)", Checked = false })
            using (var listing = new CheckBox { Left = 16, Top = 282, Width = 700, Text = "Explicitly permit PUBLIC directory COUNTS, max64 entries (NO names or contents)", Checked = false })
            using (var renames = new CheckBox { Left = 16, Top = 314, Width = 700, Text = "Explicitly permit SAME-PARENT helper-owned FILE rename, NO replacement or deletion", Checked = false })
            using (var named = new CheckBox { Left = 16, Top = 346, Width = 700, Text = "Enroll an explicit PUBLIC named-listing manifest (max8 entries; NOT arbitrary names)", Checked = false })
            using (var deletes = new CheckBox { Left = 16, Top = 378, Width = 700, Text = "Authorize WHOLE helper-owned test-object DELETION + TEST STREAMS; trees refuse foreign children", Checked = false })
            using (var processes = new CheckBox { Left = 16, Top = 410, Width = 700, Text = "Authorize bounded owned IDLE fixture process start/stop (4 slots, 30s, never arbitrary PID)", Checked = false })
            using (var generated = new CheckBox { Left = 16, Top = 442, Width = 700, Text = "Authorize code-GENERATED PUBLIC fixture files <=1MiB, CreateNew only, never caller bytes", Checked = false })
            using (var sink = new CheckBox { Left = 16, Top = 474, Width = 700, Text = "Authorize PUBLIC_ALNUM input ONLY into this owned child's focused public sink; no clipboard", Checked = false })
            {
                form.Controls.Add(new Label { Text = "GUEST-SIDE MANUAL BOOTSTRAP ONLY. No VM is provisioned or password read.\nUse an existing NON-SECRET disposable fixture root, never credentials/keys.\nCopy the exact host registration binding (not a password); no default root.", Left = 16, Top = 12, Width = 700, Height = 58 });
                form.Controls.Add(new Label { Text = "Host target binding (64 uppercase hex):", Left = 16, Top = 70, Width = 700 });
                form.Controls.Add(new Label { Text = "Exact root alias:", Left = 16, Top = 128, Width = 700 });
                form.Controls.Add(new Label { Text = "Existing guest fixture root:", Left = 16, Top = 186, Width = 700 });
                var browse = new Button { Text = "Choose root", Left = 600, Top = 205, Width = 115 };
                browse.Click += delegate { using (var picker = new FolderBrowserDialog()) { picker.Description = "Existing NON-SECRET guest fixture root (no automatic creation/ACL change)"; picker.ShowNewFolderButton = false; if (picker.ShowDialog(form) == DialogResult.OK) path.Text = picker.SelectedPath; } };
                var review = new Button { Text = "Review", Left = 470, Top = 540, Width = 115, DialogResult = DialogResult.OK };
                var cancel = new Button { Text = "Cancel", Left = 600, Top = 540, Width = 115, DialogResult = DialogResult.Cancel };
                form.Controls.AddRange(new Control[] { target, alias, path, browse, owned, listing, renames, named, deletes, processes, generated, sink, review, cancel }); form.CancelButton = cancel; form.AcceptButton = cancel;
                if (form.ShowDialog() != DialogResult.OK) return 2;
                string image = FixtureProtocol.ImageHash(typeof(GuestHelperProgram).Assembly.Location);
                GuestRootRecord record = GuestRootRecord.Capture(target.Text, alias.Text, path.Text, image);
                record.OwnedMutations = owned.Checked;
                record.PublicListing = listing.Checked;
                record.OwnedRenames = renames.Checked;
                record.OwnedDeletes = deletes.Checked;
                record.OwnedProcesses = processes.Checked;
                record.GeneratedFixtures = generated.Checked;
                record.OwnedSink = sink.Checked;
                if (named.Checked) { record.ApprovedListing = NamedManifest(); if (record.ApprovedListing == null) return 2; }
                string namedDetail = record.ApprovedListing == null ? "NO named-listing grant." : "PUBLIC named manifest digest: " + record.ApprovedListing.Digest() + "\n" + String.Join("\n", record.ApprovedListing.Lines()) + "\nOnly these enrolled names/kinds may be reported; unknown entries refuse.";
                namedDetail += record.OwnedDeletes ? "\nIRREVERSIBLE WHOLE-OWNED-TEST-OBJECT DELETION INCLUDING ALL TEST STREAMS. Tree children must ALL be helper-owned; foreign objects refuse. Separate host policy grant required; operation prompts deferred." : "\nNO deletion grant.";
                namedDetail += record.OwnedProcesses ? "\nOWNED IDLE PROCESS supervisor: fixed self-image only, original process handles, owner-only local pipe, 4 slots, 30-second expiry/revocation. NO arbitrary PID/program. Separate host policy grant required; operation prompts deferred." : "\nNO owned-process grant.";
                namedDetail += record.GeneratedFixtures ? "\nGENERATED PUBLIC fixture bytes <=1MiB: fixed public recipe, new public ID, CreateNew only, no imported/caller data. This is preparation, NOT host/guest transfer. Separate host grant required." : "\nNO generated-data grant.";
                namedDetail += record.OwnedSink ? "\nOWNED PUBLIC FIXTURE SINK: only fixed PUBLIC_ALNUM sample to this child's own focused textbox; no global keys, clipboard, arbitrary text/HWND, or text readback. Separate process+host sink grants required." : "\nNO public-sink input grant.";
                if (Native.MessageBoxW(IntPtr.Zero, "Enroll this exact NON-SECRET root?\n" + record.RootPath + "\nAlias: " + record.Alias + "\nTarget binding: " + record.TargetBinding + "\nImage SHA256: " + image + "\nI confirm no passwords/keys/private data belong in this fixture root.\n" + (record.OwnedMutations ? "Additional opt-in: NEW EMPTY object creation only, NO replacement/deletion; exact host policy still required." : "NO creation grant.") + "\n" + (record.PublicListing ? "Additional opt-in: PUBLIC immediate-directory COUNTS only, max64; no names or contents." : "NO count-only enumeration grant.") + "\n" + (record.OwnedRenames ? "Additional opt-in: same-parent helper-owned FILE rename, exact file ID, primary zero; NO replacement/deletion. Streams preserved, not inspected." : "NO rename grant.") + "\n" + namedDetail + "\nConfigured operations run unattended; this dialog is ROOT SETUP, not per-operation approval. No other roots/data authorized.", "Review guest fixture SETUP", 0x4 | 0x100 | 0x30 | 0x40000) != 6) return 2;
                new GuestRootStore().Save(record);
                using (var receipt = new Form { Text = "Non-secret enrollment receipt - copy to host policy", ClientSize = new Size(780, 340), StartPosition = FormStartPosition.CenterScreen })
                using (var details = new TextBox { ReadOnly = true, Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Segoe UI", 10), Text = UiText.Lines("Protocol: 4\nTarget binding: " + record.TargetBinding + "\nRoot alias: " + record.Alias + "\nEnrollment ID (PUBLIC generation, NOT a secret/token): " + record.EnrollmentId + "\nImage SHA256: " + image + "\nGuest root: " + record.RootPath + "\nOwned-empty creation opt-in: " + record.OwnedMutations + "\nPublic directory counts opt-in: " + record.PublicListing + "\nSame-parent owned-file rename opt-in: " + record.OwnedRenames + "\n" + namedDetail + "\nNo contents/account/credentials were returned. This receipt does NOT prove a malicious guest is trustworthy.") })
                { receipt.Controls.Add(details); receipt.ShowDialog(); }
                return 0;
            }
        }
        private static ApprovedListing NamedManifest()
        {
            using (var form = new Form { Text = "Enroll ONLY explicitly PUBLIC fixture names", ClientSize = new Size(740, 400), FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, StartPosition = FormStartPosition.CenterScreen })
            using (var lines = new TextBox { Left = 12, Top = 100, Width = 716, Height = 230, Multiline = true, ScrollBars = ScrollBars.Vertical, MaxLength = 4096 })
            {
                form.Controls.Add(new Label { Left = 12, Top = 12, Width = 716, Height = 82, Text = "One relativeDirectory|entryAlias|basename|KIND per line. KIND is literal file OR directory.\nOne exact relative directory, 1..8 public entries. No passwords/keys/private names.\nHost must enroll the SAME case-sensitive manifest; digest binds slot meanings.\nNo arbitrary names/content are returned. Existing count/creation/rename flags grant NONE of this." });
                var save = new Button { Text = "Review manifest", Left = 470, Top = 350, Width = 130, DialogResult = DialogResult.OK };
                var cancel = new Button { Text = "Cancel", Left = 610, Top = 350, Width = 115, DialogResult = DialogResult.Cancel };
                form.Controls.AddRange(new Control[] { lines, save, cancel }); form.CancelButton = cancel; form.AcceptButton = cancel;
                if (form.ShowDialog() != DialogResult.OK) return null;
                return ApprovedListing.ParseLines(lines.Lines);
            }
        }
    }
}

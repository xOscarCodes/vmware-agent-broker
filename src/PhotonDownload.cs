using System;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace GuestBroker
{
    [DataContract]
    internal sealed class PhotonPolicy
    {
        [DataMember(IsRequired = true)] internal string Machine;
        [DataMember(IsRequired = true)] internal ExportRoot Root;
        [DataMember(EmitDefaultValue = false)] internal string ExistingLicenseEvidence, LicenseHash;
        internal void Validate(string machine)
        {
            if (Machine != machine || Root == null || !Target.Hex(Root.Identity, 64)) throw new BrokerError("photon_policy_required"); HostPaths.ApprovedRoot(Root.Path);
            if (Root.Path.Length > 70 || ExistingLicenseEvidence != null && (!Target.Hex(ExistingLicenseEvidence, 32) || LicenseHash != PhotonDownload.LicenseHash) || ExistingLicenseEvidence == null && LicenseHash != null) throw new BrokerError("photon_policy_required");
        }
    }
    internal interface IPhotonSource { string VerifyLicense(); Stream OpenImage(out long length); }
    internal sealed class OfficialPhotonSource : IPhotonSource
    {
        internal static void DemandEndpoint(string url)
        {
            if (url != PhotonDownload.DescriptorUrl && url != PhotonDownload.ImageUrl) throw new BrokerError("photon_source_refused");
        }
        internal static HttpWebRequest CreateRequest(string url)
        {
            // Exact compile-time official resources only. No redirect, auth,
            // default credentials, cookies, proxy, caller URL or certificate bypass.
            DemandEndpoint(url);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var request = (HttpWebRequest)WebRequest.Create(url); request.Method = "GET"; request.AllowAutoRedirect = false;
            request.Proxy = null; request.UseDefaultCredentials = false; request.Credentials = null; request.CookieContainer = null;
            request.Timeout = 20000; request.ReadWriteTimeout = 20000; request.AutomaticDecompression = DecompressionMethods.None;
            return request;
        }
        internal static void DemandResponse(string url, HttpStatusCode status, Uri responseUri)
        {
            DemandEndpoint(url);
            if (status != HttpStatusCode.OK || responseUri == null || responseUri.AbsoluteUri != url) throw new BrokerError("photon_source_refused");
        }
        private static HttpWebResponse Open(string url)
        {
            var response = (HttpWebResponse)CreateRequest(url).GetResponse();
            try { DemandResponse(url, response.StatusCode, response.ResponseUri); return response; }
            catch { response.Dispose(); throw; }
        }
        public string VerifyLicense()
        {
            using (HttpWebResponse response = Open(PhotonDownload.DescriptorUrl))
            using (Stream stream = response.GetResponseStream())
            using (var data = new MemoryStream())
            {
                var bytes = new byte[4096]; int read;
                while ((read = stream.Read(bytes, 0, bytes.Length)) != 0) { if (data.Length + read > 262144) throw new BrokerError("photon_source_refused"); data.Write(bytes, 0, read); }
                string text = new UTF8Encoding(false, true).GetString(data.ToArray());
                using (XmlReader xml = XmlReader.Create(new StringReader(text), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 262144 })) while (xml.Read()) { }
                MatchCollection sections = Regex.Matches(text, @"<EulaSection>[\s\S]*?</EulaSection>");
                if (sections.Count != 1 || HostMetadata.Hash(sections[0].Value) != PhotonDownload.LicenseHash || !sections[0].Value.Contains("By downloading or using an Offering")) throw new BrokerError("photon_license_changed");
                return PhotonDownload.LicenseHash;
            }
        }
        private sealed class ResponseStream : Stream
        {
            private readonly HttpWebResponse response; private readonly Stream inner;
            internal ResponseStream(HttpWebResponse response) { this.response = response; inner = response.GetResponseStream(); }
            public override bool CanRead { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
            public override int Read(byte[] buffer, int offset, int count) { return inner.Read(buffer, offset, count); }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long length) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
            protected override void Dispose(bool disposing) { if (disposing) { inner.Dispose(); response.Dispose(); } base.Dispose(disposing); }
        }
        public Stream OpenImage(out long length)
        {
            HttpWebResponse response = Open(PhotonDownload.ImageUrl); length = response.ContentLength;
            if (length < PhotonDownload.Minimum || length > PhotonDownload.Maximum) { response.Dispose(); throw new BrokerError("photon_size_refused"); }
            return new ResponseStream(response);
        }
    }
    internal static class PhotonDownload
    {
        internal const string ImageUrl = "https://packages.broadcom.com/photon/5.0/GA/ova/photon-hw15-5.0-dde71ec57.x86_64.ova";
        internal const string DescriptorUrl = "https://packages.broadcom.com/photon/5.0/GA/ovf/photon-hw15-5.0-dde71ec57.x86_64/photon-hw15-5.0-dde71ec57.x86_64.ovf";
        internal const string LicenseHash = "8972C350E94198319988545474177DD5074052D91F5E35B86E5928D6471948AF";
        internal const string ImageSha512 = "6BD6A307745ADB00B8452013F2C308C9ABEFD24A9D82611E8A1551AFB965873388EBDE81A34296DC0AD2FA7F0F7B4CD3924701ABDE0C963EA40B363C444BB037";
        internal const long Minimum = 256L * 1024 * 1024, Maximum = 400L * 1024 * 1024;
        internal static long CopyChecked(Stream input, FileStream output, long expectedLength, long maximum, string expectedHash)
        {
            if (expectedLength < 1 || expectedLength > maximum || output.Length != 0 || !FixtureProtocol.Hex(expectedHash, 128)) throw new BrokerError("photon_size_refused");
            using (var sha = SHA512.Create())
            {
                var bytes = new byte[65536]; long total = 0; int read;
                while ((read = input.Read(bytes, 0, bytes.Length)) != 0)
                {
                    if (read > expectedLength - total) throw new BrokerError("photon_size_refused");
                    output.Write(bytes, 0, read); sha.TransformBlock(bytes, 0, read, bytes, 0); total += read;
                }
                sha.TransformFinalBlock(new byte[0], 0, 0); output.Flush(true);
                if (total != expectedLength || BitConverter.ToString(sha.Hash).Replace("-", "") != expectedHash) throw new BrokerError("photon_integrity_failed");
                output.Position = 0;
                using (var stored = SHA512.Create()) if (BitConverter.ToString(stored.ComputeHash(output)).Replace("-", "") != expectedHash) throw new BrokerError("photon_integrity_failed");
                return total;
            }
        }
        internal static void Execute(HostMetadata store, IPhotonSource source, OperationReport report)
        {
            using (store.Lock()) using (var deadline = new Deadline(600000))
            {
                PhotonPolicy policy = store.Read<PhotonPolicy>("photon.json"); if (policy == null) throw new BrokerError("photon_policy_required"); policy.Validate(store.MachineBinding);
                // Download itself is assent under this particular EULA. This is
                // a prior exact-terms applicability/owner-authorization evidence
                // gate, NEVER an implicit acceptance or per-operation UI flag.
                // ExistingLicenseEvidence is retained as the compatible wire name.
                if (policy.ExistingLicenseEvidence == null || policy.LicenseHash != LicenseHash) throw new BrokerError("photon_existing_license_required");
                if (source.VerifyLicense() != LicenseHash) throw new BrokerError("photon_license_changed");
                using (PinnedDirectory parent = PinnedDirectory.Open(policy.Root.Path))
                {
                    if (parent.Identity != policy.Root.Identity) throw new BrokerError("export_root_identity_changed");
                    string id = Guid.NewGuid().ToString("N").ToUpperInvariant(), path = Path.Combine(policy.Root.Path, "photon-" + id);
                    if (!HostPaths.CreatePrivateDirectory(path)) throw new BrokerError("transfer_destination_exists");
                    using (PinnedDirectory root = PinnedDirectory.Open(path))
                    {
                        try
                        {
                            long length;
                            using (Stream input = source.OpenImage(out length))
                            using (var file = new FileStream(Path.Combine(path, "photon.ova"), FileMode.CreateNew, FileSystemRights.Read | FileSystemRights.Write, FileShare.None, 65536, FileOptions.SequentialScan, HostPaths.FileSecurity()))
                            {
                                if (length < Minimum || length > Maximum) throw new BrokerError("photon_size_refused");
                                report.DownloadBytes = CopyChecked(input, file, length, Maximum, ImageSha512);
                            }
                            using (var provenance = new FileStream(Path.Combine(path, "provenance.txt"), FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.None, HostPaths.FileSecurity()))
                            {
                                byte[] text = Encoding.UTF8.GetBytes(ImageUrl + "\nSHA512 " + ImageSha512 + "\nEULA-SHA256 " + LicenseHash + "\nPrior exact-terms applicability/owner authorization evidence " + policy.ExistingLicenseEvidence + "\nDOWNLOAD ONLY: no import, boot, VM registration, account, network configuration or additional agreement acceptance.\n"); provenance.Write(text, 0, text.Length); provenance.Flush(true);
                            }
                            report.PhotonId = id; report.Completion = "official_photon_image_verified";
                        }
                        catch (Exception) { Diagnostics.Fault(); throw new BrokerError("photon_download_outcome_unknown"); } // No partial-file cleanup or resume.
                    }
                }
            }
        }
    }
}

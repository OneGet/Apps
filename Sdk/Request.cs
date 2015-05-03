// 
//  Copyright (c) Microsoft Corporation. All rights reserved. 
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//  http://www.apache.org/licenses/LICENSE-2.0
//  
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  

namespace PackageManagement.AppSyndication.Sdk {
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Threading;
    using Microsoft.PackageManagement.SwidTag;
    using Microsoft.PackageManagement.SwidTag.Utility;
    using Navigation;
    using Resources;
    using Directory = System.IO.Directory;
    using File = System.IO.File;

    public abstract class Request {
        private Dictionary<string, string[]> _options;
        private string[] _packageSources;

        public Dictionary<string, string[]> Options {
            get {
                return _options ?? (_options = OptionKeys.Where(each => !string.IsNullOrWhiteSpace(each)).ToDictionary(k => k, (k) => (GetOptionValues(k) ?? new string[0]).ToArray()));
            }
        }

        public IEnumerable<string> PackageSources {
            get {
                return _packageSources ?? (_packageSources = (Sources ?? new string[0]).ToArray());
            }
        }

        /// <summary>
        ///     Yield values in a dictionary as key/value pairs. (one pair for each value in each key)
        /// </summary>
        /// <param name="dictionary"></param>
        /// <returns></returns>
        public bool Yield(Dictionary<string, string[]> dictionary) {
            return dictionary.All(Yield);
        }

        public bool Yield(KeyValuePair<string, string[]> pair) {
            if (pair.Value.Length == 0) {
                return YieldKeyValuePair(pair.Key, null);
            }
            return pair.Value.All(each => YieldKeyValuePair(pair.Key, each));
        }

        public bool Error(ErrorCategory category, string targetObjectValue, string messageText, params object[] args) {
            return Error(messageText, category.ToString(), targetObjectValue, FormatMessageString(messageText, args));
        }

        public bool Warning(string messageText, params object[] args) {
            return Warning(FormatMessageString(messageText, args));
        }

        public bool Message(string messageText, params object[] args) {
            return Message(FormatMessageString(messageText, args));
        }

        public bool Verbose(string messageText, params object[] args) {
            return Verbose(FormatMessageString(messageText, args));
        }

        public bool Debug(string messageText, params object[] args) {
            return Debug(FormatMessageString(messageText, args));
        }

        public int StartProgress(int parentActivityId, string messageText, params object[] args) {
            return StartProgress(parentActivityId, FormatMessageString(messageText, args));
        }

        public bool Progress(int activityId, int progressPercentage, string messageText, params object[] args) {
            return Progress(activityId, progressPercentage, FormatMessageString(messageText, args));
        }

        public string GetOptionValue(string name) {
            // get the value from the request
            return (GetOptionValues(name) ?? Enumerable.Empty<string>()).LastOrDefault();
        }

        private static string FixMeFormat(string formatString, object[] args) {
            if (args == null || args.Length == 0) {
                // not really any args, and not really expectng any
                return formatString.Replace('{', '\u00ab').Replace('}', '\u00bb');
            }
            return args.Aggregate(formatString.Replace('{', '\u00ab').Replace('}', '\u00bb'), (current, arg) => current + string.Format(CultureInfo.CurrentCulture, " \u00ab{0}\u00bb", arg));
        }

        internal string GetMessageStringInternal(string messageText) {
            return Messages.ResourceManager.GetString(messageText);
        }

        internal string FormatMessageString(string messageText, params object[] args) {
            try {

                if (string.IsNullOrEmpty(messageText)) {
                    return string.Empty;
                }

                if (args == null) {
                    return messageText;
                }

                if (messageText.StartsWith(Constants.MSGPrefix, true, CultureInfo.CurrentCulture)) {
                    // check with the caller first, then with the local resources, and fallback to using the messageText itself.
                    messageText = GetMessageString(messageText.Substring(Constants.MSGPrefix.Length), GetMessageStringInternal(messageText) ?? messageText) ?? GetMessageStringInternal(messageText) ?? messageText;
                }

                // if it doesn't look like we have the correct number of parameters
                // let's return a fix-me-format string.
                var c = messageText.ToCharArray().Where(each => each == '{').Count();
                if (c < args.Length) {
                    return FixMeFormat(messageText, args);
                }
                return string.Format(CultureInfo.CurrentCulture, messageText, args);
            } catch {
                return FixMeFormat(messageText, args);
            }
        }
    

    public bool YieldDynamicOption(string name, string expectedType, bool isRequired, IEnumerable<string> permittedValues) {
            return YieldDynamicOption(name, expectedType, isRequired) && (permittedValues ?? Enumerable.Empty<string>()).All(each => YieldKeyValuePair(name, each));
        }

        public string DownloadFile(Uri remoteLocation, string localFilename,int timeoutMilliseconds, bool showProgress) {
            if (remoteLocation == null) {
                throw new ArgumentNullException("remoteLocation");
            }

            Debug("Calling 'WebDownloader::DownloadFile' '{0}','{1}','{2}','{3}'", remoteLocation, localFilename,timeoutMilliseconds,showProgress);

            if (remoteLocation.Scheme.ToLowerInvariant() != "http" && remoteLocation.Scheme.ToLowerInvariant() != "https" && remoteLocation.Scheme.ToLowerInvariant() != "ftp") {
                Error(ErrorCategory.InvalidResult, remoteLocation.ToString(), Constants.Messages.SchemeNotSupported, remoteLocation.Scheme);
                return null;
            }

            if (localFilename == null) {
                localFilename = "downloadedFile.tmp".GenerateTemporaryFilename();
            }

            localFilename = Path.GetFullPath(localFilename);

            // did the caller pass us a directory name?
            if (Directory.Exists(localFilename)) {
                localFilename = Path.Combine(localFilename, "downloadedFile.tmp");
            }

            // make sure that the parent folder is created first.
            var folder = Path.GetDirectoryName(localFilename);
            if (!Directory.Exists(folder)) {
                Directory.CreateDirectory(folder);
            }

            // clobber an existing file if it's already there.
            // todo: in the future, we could check the md5 of the file and if the remote server supports it
            // todo: we could skip the download.
            if (File.Exists(localFilename)) {
                localFilename.TryHardToDelete();
            }

            // setup the progress tracker if the caller wanted one.
            int pid = 0;
            if (showProgress) {
                pid = StartProgress(0, "Downloading '{0}'", remoteLocation);
            }

            var webClient = new WebClient();

            // Apparently, places like Codeplex know to let this thru!
            webClient.Headers.Add("user-agent", "chocolatey command line");

            var done = new ManualResetEvent(false);

            webClient.DownloadFileCompleted += (sender, args) => {
                if (args.Cancelled || args.Error != null) {
                    localFilename = null;
                }
                done.Set();
            };

            var lastPercent = 0;

            if (showProgress) {
                webClient.DownloadProgressChanged += (sender, args) => {
                    // Progress(requestObject, 2, (int)percent, "Downloading {0} of {1} bytes", args.BytesReceived, args.TotalBytesToReceive);
                    var percent = (int)((args.BytesReceived*100)/args.TotalBytesToReceive);
                    if (percent > lastPercent) {
                        lastPercent = percent;
                        Progress(pid, (int)((args.BytesReceived*100)/args.TotalBytesToReceive), "To {0}", localFilename);
                    }
                };
            }

            // start the download 
            webClient.DownloadFileAsync(remoteLocation, localFilename);

            // wait for the completion 
            if (timeoutMilliseconds > 0) {
                if (!done.WaitOne(timeoutMilliseconds)) {
                    webClient.CancelAsync();
                    Warning(Constants.Status.TimedOut);
                    Debug("Timed out downloading '{0}'", remoteLocation.AbsoluteUri);
                    return null;
                }
            } else {
                // wait until it completes or fails on it's own
                done.WaitOne();
            }
            
            // if we don't have the file by this point, we've failed.
            if (localFilename == null || !File.Exists(localFilename)) {
                CompleteProgress(pid, false);
                Error(ErrorCategory.InvalidResult, remoteLocation.ToString(), Constants.Messages.UnableToDownload, remoteLocation.ToString(), localFilename);
                return null;
            }

            if (showProgress) {
                CompleteProgress(pid, true);
            }

            return localFilename;
        }

        public byte[] DownloadContent(Uri remoteLocation, int timeoutMilliseconds, bool showProgress) {
            if (remoteLocation == null) {
                throw new ArgumentNullException("remoteLocation");
            }
            var result = new byte[0];

            Debug("Calling 'WebDownloader::DownloadFile' '{0}','{1}','{2}'", remoteLocation, timeoutMilliseconds, showProgress);

            if (remoteLocation.Scheme.ToLowerInvariant() != "http" && remoteLocation.Scheme.ToLowerInvariant() != "https" && remoteLocation.Scheme.ToLowerInvariant() != "ftp") {
                Error(ErrorCategory.InvalidResult, remoteLocation.ToString(), Constants.Messages.SchemeNotSupported, remoteLocation.Scheme);
                return null;
            }

            // setup the progress tracker if the caller wanted one.
            int pid = 0;
            if (showProgress) {
                pid = StartProgress(0, "Downloading '{0}'", remoteLocation);
            }

            var webClient = new WebClient();

            // Apparently, places like Codeplex know to let this thru!
            webClient.Headers.Add("user-agent", "chocolatey command line");

            var done = new ManualResetEvent(false);

            webClient.DownloadDataCompleted += (sender, args) => {
                if (args.Cancelled || args.Error != null) {
                    result = new byte[0];
                }
                result = args.Result;
                done.Set();
            };

            var lastPercent = 0;

            if (showProgress) {
                webClient.DownloadProgressChanged += (sender, args) => {
                    // Progress(requestObject, 2, (int)percent, "Downloading {0} of {1} bytes", args.BytesReceived, args.TotalBytesToReceive);
                    var percent = (int)((args.BytesReceived * 100) / args.TotalBytesToReceive);
                    if (percent > lastPercent) {
                        lastPercent = percent;
                        Progress(pid, (int)((args.BytesReceived * 100) / args.TotalBytesToReceive), ".");
                    }
                };
            }

            // start the download 
            webClient.DownloadDataAsync(remoteLocation);

            // wait for the completion 
            if (timeoutMilliseconds > 0) {
                if (!done.WaitOne(timeoutMilliseconds)) {
                    webClient.CancelAsync();
                    Warning(Constants.Status.TimedOut);
                    Debug("Timed out downloading '{0}'", remoteLocation.AbsoluteUri);
                    return null;
                }
            }
            else {
                // wait until it completes or fails on it's own
                done.WaitOne();
            }

            // if we don't have the file by this point, we've failed.
            if (result.Length ==0) {
                CompleteProgress(pid, false);
                Error(ErrorCategory.InvalidResult, remoteLocation.ToString(), Constants.Messages.UnableToDownload, remoteLocation.ToString(),"");
                return result;
            }

            if (showProgress) {
                CompleteProgress(pid, true);
            }

            return result;
        }

        private static bool AnyNullOrEmpty(params string[] args) {
            return args.Any(String.IsNullOrWhiteSpace);
        }

        internal bool YieldFromSwidtag(Package provider, string requiredVersion, string minimumVersion, string maximumVersion, string searchKey) {
            if (provider == null) {
                // if the provider isn't there, just return.
                return !IsCanceled;
            }

            if (AnyNullOrEmpty(provider.Name, provider.Version, provider.VersionScheme)) {
                Debug("Skipping yield on swid due to missing field \r\n", provider.ToString());
                return !IsCanceled;
            }

            if (!String.IsNullOrWhiteSpace(requiredVersion)) {
                if (provider.Version != requiredVersion) {
                    return !IsCanceled;
                }
            }
            else {
                if (!String.IsNullOrWhiteSpace(minimumVersion) && VersionComparer.CompareVersions(provider.VersionScheme, provider.Version, minimumVersion) < 0) {
                    return !IsCanceled;
                }

                if (!String.IsNullOrWhiteSpace(maximumVersion) && VersionComparer.CompareVersions(provider.VersionScheme, provider.Version, maximumVersion) > 0) {
                    return !IsCanceled;
                }
            }
            return YieldFromSwidtag(provider, searchKey);
        }

        internal bool YieldFromSwidtag(Package pkg, string searchKey) {
            if (pkg == null) {
                return !IsCanceled;
            }

            var provider = pkg._swidtag;
            var targetFilename = provider.Links.Select(each => each.Attributes[Iso19770_2.Discovery.TargetFilename]).WhereNotNull().FirstOrDefault();
            var summary = new MetadataIndexer(provider)[Iso19770_2.Attributes.Summary.LocalName].FirstOrDefault();

            var fastPackageReference = pkg.Location.AbsoluteUri;
            lock (this) {
                if (YieldSoftwareIdentity(fastPackageReference, provider.Name, provider.Version, provider.VersionScheme, summary, null, searchKey, null, targetFilename) != null) {
                    // yield all the meta/attributes
                    if (provider.Meta.Any(
                        m => {
                            var element = AddMeta(fastPackageReference);
                            var attributes = m.Attributes;
                            return attributes.Keys.Any(key => {
                                var nspace = key.Namespace.ToString();
                                if (String.IsNullOrWhiteSpace(nspace)) {
                                    return AddMetadata(element, key.LocalName, attributes[key]) == null;
                                }

                                return AddMetadata(element, new Uri(nspace), key.LocalName, attributes[key]) == null;
                            });
                        })) {
                        return !IsCanceled;
                    }

                    if (provider.Links.Any(link => AddLink(link.HRef, link.Relationship, link.MediaType, link.Ownership, link.Use, link.Media, link.Artifact) == null)) {
                        return !IsCanceled;
                    }

                    if (provider.Entities.Any(entity => AddEntity(entity.Name, entity.RegId, entity.Role, entity.Thumbprint) == null)) {
                        return !IsCanceled;
                    }

                    if (AddMetadata(fastPackageReference, "FromTrustedSource", false.ToString()) == null) {
                        return !IsCanceled;
                    }
                }
            }
            return !IsCanceled;
        }

        #region PackageMangaement Interfaces

        public interface IProviderServices {
            bool IsElevated {get;}
            IEnumerable<object> FindPackageByCanonicalId(string canonicalId, Request requestObject);
            string GetCanonicalPackageId(string providerName, string packageName, string version, string source);
            string ParseProviderName(string canonicalPackageId);
            string ParsePackageName(string canonicalPackageId);
            string ParsePackageVersion(string canonicalPackageId);
            string ParsePackageSource(string canonicalPackageId);
            void DownloadFile(Uri remoteLocation, string localFilename, Request requestObject);
            bool IsSupportedArchive(string localFilename, Request requestObject);
            IEnumerable<string> UnpackArchive(string localFilename, string destinationFolder, Request requestObject);
            bool Install(string fileName, string additionalArgs, Request requestObject);
            bool IsSignedAndTrusted(string filename, Request requestObject);
        }

        public interface IPackageProvider {
        }

        public interface IPackageManagementService {
            int Version {get;}
            IEnumerable<string> ProviderNames {get;}
            IEnumerable<string> AllProviderNames {get;}
            IEnumerable<IPackageProvider> PackageProviders {get;}
            IEnumerable<IPackageProvider> SelectProvidersWithFeature(string featureName);
            IEnumerable<IPackageProvider> SelectProvidersWithFeature(string featureName, string value);
            IEnumerable<IPackageProvider> SelectProviders(string providerName, Request requestObject);
            bool RequirePackageProvider(string requestor, string packageProviderName, string minimumVersion, Request requestObject);
        }

        #endregion

        #region core-apis

        public abstract dynamic PackageManagementService {get;}

        public abstract IProviderServices ProviderServices {get;}

        #endregion

        #region copy host-apis

        /* Synced/Generated code =================================================== */
        public abstract bool IsCanceled {get;}

        public abstract string GetMessageString(string messageText, string defaultText);

        public abstract bool Warning(string messageText);

        public abstract bool Error(string id, string category, string targetObjectValue, string messageText);

        public abstract bool Message(string messageText);

        public abstract bool Verbose(string messageText);

        public abstract bool Debug(string messageText);

        public abstract int StartProgress(int parentActivityId, string messageText);

        public abstract bool Progress(int activityId, int progressPercentage, string messageText);

        public abstract bool CompleteProgress(int activityId, bool isSuccessful);

        /// <summary>
        ///     Used by a provider to request what metadata keys were passed from the user
        /// </summary>
        /// <returns></returns>
        public abstract IEnumerable<string> OptionKeys {get;}

        /// <summary>
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public abstract IEnumerable<string> GetOptionValues(string key);

        public abstract IEnumerable<string> Sources {get;}

        public abstract string CredentialUsername {get;}

        public abstract SecureString CredentialPassword {get;}

        public abstract bool ShouldBootstrapProvider(string requestor, string providerName, string providerVersion, string providerType, string location, string destination);

        public abstract bool ShouldContinueWithUntrustedPackageSource(string package, string packageSource);

        public abstract bool AskPermission(string permission);

        public abstract bool IsInteractive {get;}

        public abstract int CallCount {get;}

        #endregion

        #region copy response-apis

        /* Synced/Generated code =================================================== */

        /// <summary>
        ///     Used by a provider to return fields for a SoftwareIdentity.
        /// </summary>
        /// <param name="fastPath"></param>
        /// <param name="name"></param>
        /// <param name="version"></param>
        /// <param name="versionScheme"></param>
        /// <param name="summary"></param>
        /// <param name="source"></param>
        /// <param name="searchKey"></param>
        /// <param name="fullPath"></param>
        /// <param name="packageFileName"></param>
        /// <returns></returns>
        public abstract string YieldSoftwareIdentity(string fastPath, string name, string version, string versionScheme, string summary, string source, string searchKey, string fullPath, string packageFileName);

        public abstract string AddMetadata(string name, string value);

        public abstract string AddMetadata(string elementPath, string name, string value);

        public abstract string AddMetadata(string elementPath, Uri @namespace, string name, string value);

        public abstract string AddMeta(string elementPath);

        public abstract string AddEntity(string name, string regid, string role, string thumbprint);

        public abstract string AddLink(Uri referenceUri, string relationship, string mediaType, string ownership, string use, string appliesToMedia, string artifact);

        public abstract string AddDependency(string providerName, string packageName, string version, string source, string appliesTo);

        public abstract string AddPayload();

        public abstract string AddEvidence(DateTime date, string deviceId);

        public abstract string AddDirectory(string elementPath, string directoryName, string location, string root, bool isKey);

        public abstract string AddFile(string elementPath, string fileName, string location, string root, bool isKey, long size, string version);

        public abstract string AddProcess(string elementPath, string processName, int pid);

        public abstract string AddResource(string elementPath, string type);

        /// <summary>
        ///     Used by a provider to return fields for a package source (repository)
        /// </summary>
        /// <param name="name"></param>
        /// <param name="location"></param>
        /// <param name="isTrusted"></param>
        /// <param name="isRegistered"></param>
        /// <param name="isValidated"></param>
        /// <returns></returns>
        public abstract bool YieldPackageSource(string name, string location, bool isTrusted, bool isRegistered, bool isValidated);

        /// <summary>
        ///     Used by a provider to return the fields for a Metadata Definition
        ///     The cmdlets can use this to supply tab-completion for metadata to the user.
        /// </summary>
        /// <param name="name">the provider-defined name of the option</param>
        /// <param name="expectedType"> one of ['string','int','path','switch']</param>
        /// <param name="isRequired">if the parameter is mandatory</param>
        /// <returns></returns>
        public abstract bool YieldDynamicOption(string name, string expectedType, bool isRequired);

        public abstract bool YieldKeyValuePair(string key, string value);

        public abstract bool YieldValue(string value);

        #endregion
    }
}
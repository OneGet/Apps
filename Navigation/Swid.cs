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

namespace PackageManagement.AppSyndication.Navigation {
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Text;
    using Microsoft.PackageManagement.SwidTag;
    using Microsoft.PackageManagement.SwidTag.Utility;
    using Sdk;

    internal class Swid {
        private const int SwidDownloadTimeout = 8000;
        internal readonly Request _request;
        internal readonly Swidtag _swidtag;
        private bool _timedOut;

        [SuppressMessage("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Swid(Request request, Swidtag swidtag) {
            _request = request;
            _swidtag = swidtag;
        }

        internal Swid(Request request, IEnumerable<Link> mirrors) {
            _request = request;
            _swidtag = DownloadSwidtag(mirrors);
        }

        internal Swid(Request request, IEnumerable<Uri> mirrors) {
            _request = request;
            _swidtag = DownloadSwidtag(mirrors);
        }

        internal Uri Location {get; private set;}

        [SuppressMessage("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        protected IEnumerable<IGrouping<string, Link>> Artifacts {
            get {
                return IsValid ? _swidtag.Links.GroupBy(link => string.IsNullOrEmpty(link.Artifact) ? "noartifact".GenerateTemporaryFilename() : link.Artifact) : Enumerable.Empty<IGrouping<string, Link>>();
            }
        }

        protected IEnumerable<IGrouping<string, Link>> Feeds {
            get {
                return IsValid
                    ? _swidtag.Links.Where(link => link.Relationship == Iso19770_2.Relationship.Feed).GroupBy(link => string.IsNullOrEmpty(link.Artifact) ? "noartifact".GenerateTemporaryFilename() : link.Artifact) : Enumerable.Empty<IGrouping<string, Link>>();
            }
        }

        protected IEnumerable<IGrouping<string, Link>> Packages {
            get {
                return IsValid
                    ? _swidtag.Links.Where(link => link.Relationship == Iso19770_2.Relationship.Package).GroupBy(link => string.IsNullOrEmpty(link.Artifact) ? "noartifact".GenerateTemporaryFilename() : link.Artifact)
                    : Enumerable.Empty<IGrouping<string, Link>>();
            }
        }

        protected IEnumerable<IGrouping<string, Link>> More {
            get {
                return _swidtag.Links.Where(link => link.Relationship == Iso19770_2.Relationship.Supplemental).GroupBy(link => string.IsNullOrEmpty(link.Artifact) ? "noartifact".GenerateTemporaryFilename() : link.Artifact);
            }
        }

        internal virtual bool IsValid {
            get {
                return _swidtag != null;
            }
        }

        private Swidtag DownloadSwidtag(IEnumerable<Uri> locations) {
            foreach (var location in locations.WhereNotNull()) {
                try {
                    var content = _request.DownloadContent(location, SwidDownloadTimeout, false);
                    if (_timedOut) {
                        // try one more time...
                        content = _request.DownloadContent(location, SwidDownloadTimeout, false);
                    }
                    if (content.Length > 0) {
                        var document = Encoding.UTF8.GetString(content);
                        Swidtag tag = null;
                        if (document.StartsWith("<?xml")) {
                            tag = Swidtag.LoadXml(document);
                        }
                        if (tag == null && document.StartsWith("{")) {
                            tag = Swidtag.LoadJson(document);
                        }
                        if (tag == null ) {
                            tag = Swidtag.LoadHtml(document);
                        }
                        if (tag != null) {
                            Location = location;
                            return tag;
                        }
                    }
                } catch (Exception e) {
                    e.Dump();
                }
            }
            return null;
        }

        internal Swidtag DownloadSwidtag(IEnumerable<Link> locations) {
            return DownloadSwidtag(locations.Where(link => link != null && link.HRef != null).Select(link => link.HRef));
        }

        protected IEnumerable<IGrouping<string, Link>> PackagesFilteredByName(string name) {
            if (string.IsNullOrWhiteSpace(name)) {
                return Packages;
            }

            return Packages.Where(packageGroup => {
                var n = packageGroup.FirstOrDefault().Attributes[Iso19770_2.Discovery.Name];
                return (string.IsNullOrEmpty(n) || name.EqualsIgnoreCase(n));
            });
        }
    }
}
#
# spec file for package cockpit-selinux-fixer
#
# Copyright (c) 2026 Neal Haas
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License).
#

Name:           cockpit-selinux-fixer
Version:        0.1.0
Release:        0
Summary:        Cockpit page that finds and fixes SELinux denials
License:        GPL-3.0-or-later
URL:            https://github.com/GITHUB_USER/cockpit-selinux-fixer
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  make
BuildRequires:  python3
Requires:       checkpolicy
Requires:       cockpit-bridge >= 300
Requires:       cockpit-system
Requires:       policycoreutils
Requires:       policycoreutils-python-utils
Requires:       python3
Recommends:     audit
BuildArch:      noarch

%description
SELinux Fixer adds a "Tools > SELinux Fixer" page to Cockpit. It reads
SELinux denials (AVC messages) from the audit log and the systemd journal,
explains them in plain language and, when you agree, fixes them: restoring
file labels, labeling custom data directories and ports, turning on policy
booleans, scheduling a relabel, or as a last resort installing a local policy
module. Every fix is recorded, and most can be undone.

Also ships the selinux-fixer command line tool. Works on openSUSE
Tumbleweed, Leap 16 and the transactional Kalpa, Aeon and MicroOS systems.

%prep
%autosetup

%build

%install
%make_install PREFIX=%{_prefix}

%check
make check

%files
%license LICENSE
%doc README.md
%{_bindir}/selinux-fixer
%{_datadir}/cockpit/selinux-fixer

%changelog

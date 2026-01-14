%global debug_package %{nil}

Name:           cvetool
Version:        0.0.1
Release:        1%{?dist}
Summary:        A Claircore-based CVE manager

License:        Apache-2.0
URL:            https://github.com/ComplianceAsCode/cvetool
Source0:        https://github.com/ComplianceAsCode/cvetool/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  golang
BuildRequires:  git
Requires:       glibc

%description
%{summary}

%prep
%setup -q

%build
export CGO_CPPFLAGS="${CPPFLAGS}"
export CGO_CFLAGS="${CFLAGS}"
export CGO_CXXFLAGS="${CXXFLAGS}"
export CGO_LDFLAGS="${LDFLAGS}"
export GOFLAGS="-buildmode=pie -trimpath -mod=readonly -modcacherw"

go mod tidy
go build -ldflags="-linkmode=external -X main.Version=%{version}-%{release}" ./cmd/cvetool

%install
install -Dm0755 %{name} %{buildroot}%{_bindir}/%{name}

%files
%{_bindir}/%{name}
%license LICENSE
%doc README.md

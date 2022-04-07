ARG WINDOWS_VERSION

FROM mcr.microsoft.com/windows/nanoserver:${WINDOWS_VERSION}

ENV PATH="C:\Program Files\PowerShell;C:\utils;C:\Windows\system32;C:\Windows;"

COPY install-calico-windows.ps1 /
COPY calico-windows.zip /

ENTRYPOINT ["powershell"]


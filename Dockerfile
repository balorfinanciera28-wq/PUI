# escape=`
FROM python:3.11.9-windowsservercore-1809

SHELL ["powershell", "-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]
WORKDIR C:\app

# The application defaults to ODBC Driver 17 for SQL Server.
RUN Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2249004' -OutFile C:\msodbcsql17.msi; `
    Start-Process msiexec.exe -ArgumentList '/i', 'C:\msodbcsql17.msi', '/quiet', '/norestart', 'IACCEPTMSODBCSQLLICENSETERMS=YES' -Wait; `
    Remove-Item C:\msodbcsql17.msi -Force

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 5000
CMD ["python", "runserver.py"]

:: Call this from the Visual Studio Developer CMD

:: Builds against the release configuration
:: Automatically increases version number

@echo off

set PROFILE=release
set PRODUCT=TameMyCerts.REST
set XMLDOCS=%PRODUCT%.xml

rmdir src\%PRODUCT%\bin\%PROFILE% /S /Q
mkdir src\%PRODUCT%\bin\%PROFILE%
mkdir src\%PRODUCT%\bin\%PROFILE%\wwwroot

MSBuild.exe ^
src\%PRODUCT%\%PRODUCT%.csproj ^
-property:Configuration=%PROFILE% ^
/p:GenerateDocumentation=true ^
/p:DocumentationFile=%XMLDOCS% ^
/p:DeployOnBuild=true ^
/p:PublishProfile=FolderProfile ^
/p:DebugSymbols=false ^
/p:DebugType=None ^
/p:CustomAfterMicrosoftCommonTargets="%VSINSTALLDIR%\MSBuild\Microsoft\VisualStudio\v%VisualStudioVersion%\TextTemplating\Microsoft.TextTemplating.targets" ^
/p:TransformOnBuild=true ^
/p:TransformOutOfDateOnly=false

copy src\%PRODUCT%\README.md src\%PRODUCT%\bin\%PROFILE%\
copy src\%PRODUCT%\LICENSE src\%PRODUCT%\bin\%PROFILE%\
copy src\%PRODUCT%\NOTICE src\%PRODUCT%\bin\%PROFILE%\
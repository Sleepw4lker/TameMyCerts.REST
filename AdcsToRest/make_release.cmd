:: Call this from the Visual Studio Developer CMD

:: Builds against the release configuration
:: Automatically increases version number

@echo off

set PROFILE=release
set XMLDOCS=AdcsToRest.Documentation.xml

rmdir bin\%PROFILE% /S /Q
mkdir bin\%PROFILE%

MSBuild.exe ^
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

copy ..\README.adoc bin\%PROFILE%\
copy ..\LICENSE bin\%PROFILE%\
copy ..\NOTICE bin\%PROFILE%\
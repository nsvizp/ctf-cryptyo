@echo off
setlocal
set ROOT_DIR=%~dp0..
set VERSION=%~1
if "%VERSION%"=="" set VERSION=1.14.2
if "%MVN%"=="" set MVN=mvn
cd /d %ROOT_DIR%
call %MVN% clean package || exit /b 1
call %MVN% javafx:jlink || exit /b 1
if exist target\myxfc rmdir /s /q target\myxfc
jpackage -n myxfc --app-version %VERSION% -m "myxfc/myxfc.Main" --runtime-image target\myxfc-runtime --dest target --java-options "--add-opens=java.base/java.lang.reflect=com.jfoenix --add-exports=javafx.controls/com.sun.javafx.scene.control.behavior=com.jfoenix --add-exports=javafx.base/com.sun.javafx.binding=com.jfoenix --add-exports=javafx.base/com.sun.javafx.event=com.jfoenix --add-exports=javafx.graphics/com.sun.javafx.stage=com.jfoenix --add-exports=javafx.graphics/com.sun.javafx.scene=com.jfoenix --add-exports=javafx.controls/com.sun.javafx.scene.control.behavior=com.jfoenix --add-exports=javafx.controls/com.sun.javafx.scene.control=com.jfoenix" --icon jpackage\ico\myxfc.ico --type app-image --description "myxfc" --vendor "myxfc" --copyright "MIT License" || exit /b 1
copy /y LICENSE target\myxfc\LICENSE
powershell -NoProfile -Command "Compress-Archive -Path 'target\myxfc' -DestinationPath 'target\myxfc-win.zip' -Force" || exit /b 1
if not exist target\myxfc-win.zip exit /b 1

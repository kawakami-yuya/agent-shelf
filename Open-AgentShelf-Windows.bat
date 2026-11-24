@echo off
chcp 65001 >nul
rem Agent Shelf を作ってブラウザで開きます（ダブルクリックで実行）
rem このウィンドウを開いている間は、画面右上の「最新にする」で作り直せます。
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python 3 が見つかりませんでした。
  echo https://www.python.org/downloads/ からインストールしてから、もう一度開いてください。
  echo （インストール時に「Add python.exe to PATH」にチェックを入れてください）
  pause
  exit /b 1
)
%PY% build.py --serve %*
if errorlevel 1 (
  echo.
  echo うまく作れませんでした。上のメッセージを確認してください。
  pause
  exit /b 1
)

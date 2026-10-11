#!/bin/bash
# Agent Shelf を作ってブラウザで開きます（ダブルクリックで実行）
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 が見つかりませんでした。"
  echo "表示された案内に従って「コマンドライン・デベロッパ・ツール」をインストールしてから、もう一度開いてください。"
  read -r -p "Enter で閉じます" _
  exit 1
fi
if python3 build.py "$@"; then
  open index.html
  echo ""
  echo "ブラウザで開きました。このウィンドウは閉じて大丈夫です。"
else
  echo ""
  echo "うまく作れませんでした。上のメッセージを確認してください。"
  read -r -p "Enter で閉じます" _
fi

#!/bin/bash
# Agent Shelf を作ってブラウザで開きます（ダブルクリックで実行）
# このウィンドウを開いている間は、画面右上の「最新にする」で作り直せます。
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 が見つかりませんでした。"
  echo "表示された案内に従って「コマンドライン・デベロッパ・ツール」をインストールしてから、もう一度開いてください。"
  read -r -p "Enter で閉じます" _
  exit 1
fi
if ! python3 build.py --serve "$@"; then
  echo ""
  echo "うまく作れませんでした。上のメッセージを確認してください。"
  read -r -p "Enter で閉じます" _
fi

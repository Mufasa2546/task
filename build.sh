#!/bin/sh
# Builds the installable app into the repo root from the shared source (index.html is also the claude.ai version).
cd "$(dirname "$0")"
{
  printf '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">\n'
  printf '<meta name="theme-color" content="#0b2340">\n<meta name="apple-mobile-web-app-capable" content="yes">\n<meta name="apple-mobile-web-app-title" content="Task">\n'
  printf '<link rel="manifest" href="manifest.webmanifest">\n<link rel="icon" href="icon.svg">\n<link rel="apple-touch-icon" href="apple-touch-icon.png">\n'
  printf '<style>:root{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0}img{max-width:100%%}[hidden]{display:none!important}</style>\n</head>\n<body>\n'
  cat src/app.html
  printf '\n</body>\n</html>\n'
} > index.html

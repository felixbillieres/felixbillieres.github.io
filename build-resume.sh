#!/usr/bin/env bash
# Recompile le CV. Necessite l'image texbuild:cv (texlive-small + titlesec).
set -e
cd "$(dirname "$0")"
docker run --rm -v "$PWD":/w -w /w texbuild:cv \
  pdflatex -interaction=nonstopmode -halt-on-error resume_optimized.tex >/dev/null
cp resume_optimized.pdf static/resume.pdf
grep -aoE 'Output written on [^ ]+ \(([0-9]+) pages?' resume_optimized.log | tail -1

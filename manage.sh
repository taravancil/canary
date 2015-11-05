#!/bin/bash
BASE_DIR="$(pwd)"
STATIC_DIR="$BASE_DIR/canary/static"
SCSS_DIR="$BASE_DIR/canary/src/scss"
CSS_DIR="$STATIC_DIR/css"
JS_DIR="$BASE_DIR/canary/src/js"
VENV="$BASE_DIR/venv"
EXIT_CODE=0

check_deps() {
  command -v "python" >/dev/null 2>&1 || echo "Python required." exit 1;

  declare -a missing
  if [ ! -d "$VENV/lib/libsass" ]; then
    print "libsass"
    missing=("${missing[@]}" "libsass")
    EXIT_CODE=1
  fi
  
  deps="sassc jsmin"
  for dep in $deps; do
    command -v "$dep" >/dev/null 2>&1 || \
      missing=("${missing[@]}" "$dep") EXIT_CODE=1;
  done
  
  if [ "$EXIT_CODE" -eq 1 ]; then
    echo >&2 "Missing ${#missing[@]} dependencies:"
    for dep in ${missing[@]}; do
      echo >&2 "- $dep"
    done
    echo >&2 "Install with $0 install_libs"
    exit 1
  fi 
}

install_libs() {
  echo "Installing libraries..."
  set -e
  cd "venv/lib"
  if [ ! -d libsass ]; then
    git clone --depth 1 https://github.com/sass/libsass.git
  fi

  if [ ! -d sassc ]; then
    git clone --depth 1 https://github.com/sass/sassc.git
  fi

  if [ ! -d jsmin ]; then
    git clone --depth 1 https://github.com/douglascrockford/JSMin.git
  fi

  cd "$VENV"
  if [ ! -f bin/sassc ]; then
    echo "Building sassc..."
    export SASS_LIBSASS_PATH="$VENV/lib/libsass"
    make -C ./lib/sassc
    mv ./lib/sassc/bin/sassc bin/sassc
  fi

  if [ ! -f bin/jsmin ]; then
    echo "Building JSMin..."
    gcc -o "bin/jsmin" ./lib/JSMIN/jsmin.c 
  fi
  
  cd ..
  echo "Done."
}

build() {
  build_css
  minify_js
}

build_css() {
  set -e
  export SASS_LIBSASS_PATH="$VENV/lib/libsass"
  echo "Building and compressing CSS..."

  # --style can be nested, expanded, compact, or compressed
  # sass-lang.com/documentation/file.SASS_REFERENCE.html#output_style
  sassc --style compressed "$SCSS_DIR/main.scss" > "$CSS_DIR/style.css"
}

minify_js() {
  set -e
  echo "Minifying JavaScript..."
  cd "$JS_DIR"
  for f in *.js; do
    jsmin <$f > $STATIC_DIR/js/min.$f
  done
  cd "$BASE_DIR"
}

test() {
  export CANARY_ENV="test"
  if [ "$#" -ge 2 ]; then
    shift
    for arg in "$@"; do 
      echo "Testing canary.$arg..."
      python -m canary.test."$arg"_test
    done
  else 
    echo "Testing canary..."
    python -m unittest discover canary "*_test.py"
  fi
}

run() {
  check_deps
  python run.py
}

case $1 in
  check_deps)
    check_deps;
    ;;
  install_libs)
    install_libs;
    ;;
  build)
    build;
    ;;
  build_css)
    build_css;
    ;;
  minify_js)
    minify_js;
    ;;
  run)
    run;
    ;;
  test)
    test $*;
    ;;
  *)
    echo "Usage: $0 \
      {build|build_css|check_libs|install_libs|test[modules]}"
    EXIT_CODE=1
esac

exit $EXIT_CODE


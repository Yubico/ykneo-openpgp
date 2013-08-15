#!/bin/sh

set -e

VERSION=$1
PGP_KEYID=$2

if [ "x$PGP_KEYID" = "x" ]; then
  echo "try with $0 VERSION PGP_KEYID"
  echo "example: $0 1.0.3 9D1C0E79"
  exit
fi

if ! test -f $JAVACARD_HOME/lib/api.jar; then
    echo "Install JCK and point environment variable JAVACARD_HOME to it"
    exit
fi

if ! head -3 NEWS  | grep -q "Version $VERSION .released `date -I`"; then
  echo "You need to update date/version in NEWS"
  exit
fi

if ! cat src/openpgpcard/OpenPGPApplet.java | grep -q "VERSION = { `echo $VERSION | awk -F. '{print "0x0" $1 ", 0x0"$2 ", 0x0"$3}'`"; then
  echo "You need to update version in OpenPGPApplet.java"
  exit
fi

if [ "x$YUBICO_GITHUB_REPO" = "x" ]; then
  echo "you need to define YUBICO_GITHUB_REPO"
  exit
fi

releasename=ykneo-openpgp-${VERSION}

git push
git tag -u ${PGP_KEYID} -m $VERSION $VERSION
git push --tags
tmpdir=`mktemp -d /tmp/release.XXXXXX`
releasedir=${tmpdir}/${releasename}
mkdir -p $releasedir
git archive $VERSION --format=tar | tar -xC $releasedir
git2cl > $releasedir/ChangeLog
tar -cz --directory=$tmpdir --file=${releasename}.tar.gz $releasename
cd $releasedir
cp /tmp/build.xml .
ant -q -DJAVACARD_HOME=$JAVACARD_HOME
cd -
cp $releasedir/bin/openpgpcard/javacard/openpgpcard.cap ${releasename}.cap
gpg --detach-sign --default-key $PGP_KEYID ${releasename}.tar.gz
gpg --detach-sign --default-key $PGP_KEYID ${releasename}.cap
$YUBICO_GITHUB_REPO/publish ykneo-openpgp $VERSION ${releasename}.tar.gz*
$YUBICO_GITHUB_REPO/publish ykneo-openpgp $VERSION ${releasename}.cap*
rm -rf $tmpdir

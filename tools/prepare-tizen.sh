# $1 corresponds to libgsignon-glib-<ver>.tar.gz 
# $2 is the destination folder
# NOTE: all the files will be extracted under destination folder (instead of destfolder/libgsignon-glib-<version>)

if [ $# -ne 2 -o -z "$1" -o -z "$2" ]; then
    echo "Invalid arguments supplied"
    echo "Usage: ./prepare-tizen.sh <archive> <destination>"
    echo "NOTE: All the files will be extracted under destfolder (instead of destfolder/libgsignon-glib-<version>)"
    exit
fi

mkdir -p $2 && \
cd $2 && \
git rm -f -r *;
tar -xzvf $1 -C $2 --strip-components 1 && \
git add -f *;

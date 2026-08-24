#!/bin/bash

# Folder główny
mkdir -p projekt/folder1/podfolderA
mkdir -p projekt/folder1/podfolderB
mkdir -p projekt/folder2/podfolderC
mkdir -p projekt/folder2/podfolderD

# Pliki tekstowe w folder1
echo "To jest plik 1 w folderze 1" >projekt/folder1/plik1.txt
echo "To jest plik 2 w folderze 1" >projekt/folder1/plik2.txt
echo "Tekst w podfolderze A" >projekt/folder1/podfolderA/plik3.txt
echo "Tekst w podfolderze B" >projekt/folder1/podfolderB/plik4.txt

# Pliki tekstowe w folder2
echo "To jest plik 1 w folderze 2" >projekt/folder2/plik5.txt
echo "To jest plik 2 w folderze 2" >projekt/folder2/plik6.txt
echo "Tekst w podfolderze C" >projekt/folder2/podfolderC/plik7.txt
echo "Tekst w podfolderze D" >projekt/folder2/podfolderD/plik8.txt

echo "Struktura folderów została utworzona!"

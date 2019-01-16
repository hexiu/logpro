package prolog

import (
	"os"
	"path/filepath"
	"regexp"
)

// ListDirAllFile 展示目录下所有的文件
func ListDirAllFile(root string) (files []string, err error) {
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// ListDirFile 展示目录下的文件
func ListDirFile(root string, peach string) (files []string, err error) {
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			if peach == "" {
				files = append(files, path)
			} else {
				reg := regexp.MustCompile(peach)
				if len(reg.FindAll([]byte(path), -1)) > 0 {
					files = append(files, path)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

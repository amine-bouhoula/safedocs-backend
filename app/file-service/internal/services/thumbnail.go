package services

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/unidoc/unipdf/v3/model"
	"github.com/unidoc/unipdf/v3/render"
)

func CreateThumbnailFromPDF(fileID string, fileContent io.Reader) (string, error) {

	body, _ := io.ReadAll(fileContent)

	filePathTmp := "/tmp/" + fileID + ".pdf"

	err := os.WriteFile(filePathTmp, body, 0644)
	if err != nil {
		log.Fatal(err)
	}

	reader, _, err := model.NewPdfReaderFromFile(filePathTmp, nil)

	if err != nil {
		return "", err
	}

	pageNum := 1 // The page number to extract
	page, err := reader.GetPage(pageNum)
	if err != nil {
		return "", err
	}

	device := render.NewImageDevice()

	outDir := "/tmp/"

	outFilename := filepath.Join(outDir, fmt.Sprintf("%s_%d_thumbnail.png", fileID, 1))
	if err = device.RenderToPath(page, outFilename); err != nil {
		log.Fatalf("Image rendering error: %v\n", err)
	}

	return outFilename, nil
}

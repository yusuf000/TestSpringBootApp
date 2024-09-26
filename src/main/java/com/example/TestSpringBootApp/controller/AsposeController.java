package com.example.TestSpringBootApp.controller;

import com.aspose.pdf.Document;
import com.aspose.pdf.HtmlSaveOptions;
import com.aspose.pdf.SaveFormat;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;

@Controller
@RequestMapping("/aspose")
public class AsposeController {
    @GetMapping("/uploadFile")
    public String uploadFile() {
        return "index";
    }

    @PostMapping("/upload")
    @ResponseBody
    public String convertFile(@RequestParam("file") MultipartFile file) throws Exception {
        // Open the source PDF document
        Document document = new Document(file.getInputStream());

// Instantiate HTML SaveOptions object
        HtmlSaveOptions htmlOptions = new HtmlSaveOptions();
        htmlOptions.PartsEmbeddingMode = HtmlSaveOptions.PartsEmbeddingModes.EmbedAllIntoHtml;
        htmlOptions.RasterImagesSavingMode = HtmlSaveOptions.RasterImagesSavingModes.AsEmbeddedPartsOfPngPageBackground;
// Specify to split the output into multiple pages
        htmlOptions.setSplitIntoPages(true);
        OutputStream out = new ByteArrayOutputStream();
// Save the document
        document.save(out);
        return out.toString();
    }
}

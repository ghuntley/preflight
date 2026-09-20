use anyhow::{Context, Result, bail};
use image::{AnimationDecoder, DynamicImage, ImageReader};
use lopdf::{Document, Object, Stream, dictionary};
use preflight::worker::{Manifest, Segment};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    io::{BufReader, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
struct Worker {
    job: PathBuf,
    manifest: Manifest,
    pixels: u64,
    depth: usize,
    embedded_count: usize,
    embedded_bytes: usize,
}
fn tool(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let mut child = Command::new(program)
        .args(args)
        .env("OMP_THREAD_LIMIT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .context("stdout")?
        .take((OUTPUT_LIMIT + 1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > OUTPUT_LIMIT {
        let _ = child.kill();
        let _ = child.wait();
        bail!("output_limit");
    }
    if !child.wait()?.success() {
        bail!("tool_failed");
    }
    Ok(output)
}
fn path(p: &Path) -> Result<&str> {
    p.to_str().context("path")
}
impl Worker {
    fn add(&mut self, text: String, page: Option<usize>, bounds: Option<[u32; 4]>) -> Result<()> {
        if self
            .manifest
            .segments
            .iter()
            .map(|s| s.text.len())
            .sum::<usize>()
            + text.len()
            > 8 * 1024 * 1024
        {
            bail!("text_limit");
        }
        self.manifest.segments.push(Segment { text, page, bounds });
        Ok(())
    }
    fn metadata(&mut self, input: &Path) -> Result<()> {
        let data = tool("exiftool", &["-json", "-a", "-u", "-G1", path(input)?])?;
        let value: serde_json::Value = serde_json::from_slice(&data)?;
        self.values(&value, None)
    }
    fn values(&mut self, v: &serde_json::Value, page: Option<usize>) -> Result<()> {
        match v {
            serde_json::Value::String(s) => {
                if let Some(encoded) = s.strip_prefix("b:")
                    && let Ok(bytes) = hex::decode(encoded)
                    && let Ok(text) = String::from_utf8(bytes)
                {
                    self.add(text, page, None)?;
                }
                self.add(s.strip_prefix("u:").unwrap_or(s).to_owned(), page, None)?;
            }
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    if [
                        "/OpenAction",
                        "/AA",
                        "/OCProperties",
                        "/XFA",
                        "/JS",
                        "/JavaScript",
                        "/RichMediaContent",
                        "/Prev",
                    ]
                    .contains(&k.as_str())
                    {
                        bail!("unsupported_pdf_feature");
                    }
                    self.values(v, page)?;
                }
            }
            serde_json::Value::Array(a) => {
                for v in a {
                    self.values(v, page)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn image(&mut self, image: DynamicImage) -> Result<()> {
        let pixels = u64::from(image.width()) * u64::from(image.height());
        if pixels > 25_000_000
            || self.pixels + pixels > 100_000_000
            || self.manifest.pages.len() >= 20
        {
            bail!("pixel_limit");
        }
        self.pixels += pixels;
        let index = self.manifest.pages.len();
        let name = format!("page-{index}.png");
        let file = self.job.join(&name);
        image.to_rgb8().save(&file)?;
        self.manifest.pages.push(name);
        let mut views = Vec::new();
        for rotation in 0..4 {
            let oriented = match rotation {
                0 => image.clone(),
                1 => image.rotate90(),
                2 => image.rotate180(),
                _ => image.rotate270(),
            };
            let oriented_path = self.job.join(format!("orientation-{rotation}.png"));
            oriented.save(&oriented_path)?;
            views.push((
                oriented_path,
                oriented.width(),
                oriented.height(),
                rotation,
                oriented.width(),
                oriented.height(),
            ));
            if oriented.width() > 2000 || oriented.height() > 2000 {
                let reduced = oriented.resize(
                    (oriented.width() / 2).max(1),
                    (oriented.height() / 2).max(1),
                    image::imageops::FilterType::Lanczos3,
                );
                let reduced_path = self.job.join(format!("reduced-{rotation}.png"));
                reduced.save(&reduced_path)?;
                views.push((
                    reduced_path,
                    reduced.width(),
                    reduced.height(),
                    rotation,
                    oriented.width(),
                    oriented.height(),
                ));
            }
        }
        for (view, width, height, rotation, oriented_width, oriented_height) in views {
            for psm in ["3", "11"] {
                let data = tool("tesseract", &[path(&view)?, "stdout", "--psm", psm, "tsv"])?;
                let mut reader = csv::ReaderBuilder::new()
                    .delimiter(b'\t')
                    .flexible(true)
                    .from_reader(data.as_slice());
                let mut groups: BTreeMap<(u32, u32, u32), Vec<Word>> = BTreeMap::new();
                for row in reader.deserialize::<Word>() {
                    let word = row?;
                    if !word.text.trim().is_empty() {
                        groups
                            .entry((word.block_num, word.par_num, word.line_num))
                            .or_default()
                            .push(word);
                    }
                }
                for words in groups.values() {
                    let mut text = String::new();
                    for (index, word) in words.iter().enumerate() {
                        if let Some(previous) = index.checked_sub(1).map(|i| &words[i]) {
                            let gap = word
                                .left
                                .saturating_sub(previous.left.saturating_add(previous.width));
                            let character_width = (previous.width
                                / (previous.text.chars().count().max(1) as u32))
                                .max(1);
                            if gap > character_width / 2 {
                                text.push(' ');
                            }
                        }
                        text.push_str(&word.text);
                    }
                    let bounds = [
                        words.iter().map(|w| w.left).min().unwrap(),
                        words.iter().map(|w| w.top).min().unwrap(),
                        words
                            .iter()
                            .map(|w| w.left.saturating_add(w.width))
                            .max()
                            .unwrap(),
                        words
                            .iter()
                            .map(|w| w.top.saturating_add(w.height))
                            .max()
                            .unwrap(),
                    ];
                    let bounds = preflight::worker::scale_bounds(
                        bounds,
                        [width, height],
                        [oriented_width, oriented_height],
                    );
                    let bounds = preflight::worker::unrotate_bounds(
                        bounds,
                        [image.width(), image.height()],
                        rotation,
                    );
                    self.add(text, Some(index), Some(bounds))?;
                }
            }
        }
        // ZBar returns 4 when there are no barcodes. Other failures are incomplete.
        let output = Command::new("zbarimg")
            .args(["--quiet", "--raw", path(&file)?])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if output.stdout.len() > OUTPUT_LIMIT {
            bail!("barcode_limit");
        }
        if output.status.success() {
            self.add(String::from_utf8(output.stdout)?, Some(index), None)?;
        } else if output.status.code() != Some(4) {
            bail!("barcode_failed");
        }
        Ok(())
    }
    fn inspect(&mut self) -> Result<()> {
        let input = self.job.join("input");
        let data = std::fs::read(&input)?;
        if data.len() > 64 * 1024 * 1024 {
            bail!("input_limit");
        }
        self.metadata(&input)?;
        if data.starts_with(b"%PDF-") {
            self.manifest.pdf = true;
            let info = String::from_utf8(tool("pdfinfo", &[path(&input)?])?)?;
            if info
                .lines()
                .any(|l| l.starts_with("Encrypted:") && !l.ends_with("no"))
            {
                bail!("encrypted_pdf");
            }
            let pages = info
                .lines()
                .find_map(|l| l.strip_prefix("Pages:"))
                .context("pages")?
                .trim()
                .parse::<usize>()?;
            if pages == 0 || pages > 20 {
                bail!("page_limit");
            }
            let json = tool(
                "qpdf",
                &["--json", "--json-stream-data=none", path(&input)?],
            )?;
            let value: serde_json::Value = serde_json::from_slice(&json)?;
            self.values(&value, None)?;
            let listing = String::from_utf8(tool("pdfdetach", &["-list", path(&input)?])?)?;
            let count = listing
                .split_whitespace()
                .next()
                .context("embedded_count")?
                .parse::<usize>()?;
            if self.depth >= 4 && count > 0 || self.embedded_count + count > 16 {
                bail!("embedded_attachment_limit");
            }
            self.embedded_count += count;
            for number in 1..=count {
                let job = self.job.join(format!("attachment-{number}"));
                std::fs::create_dir(&job)?;
                let destination = job.join("input");
                tool(
                    "pdfdetach",
                    &[
                        "-save",
                        &number.to_string(),
                        "-o",
                        path(&destination)?,
                        path(&input)?,
                    ],
                )?;
                let bytes = std::fs::read(&destination)?;
                self.embedded_bytes += bytes.len();
                if self.embedded_bytes > 64 * 1024 * 1024 {
                    bail!("embedded_bytes_limit");
                }
                if let Ok(text) = std::str::from_utf8(&bytes)
                    && !bytes.starts_with(b"%PDF-")
                    && text
                        .chars()
                        .all(|c| !c.is_control() || matches!(c, '\r' | '\n' | '\t'))
                {
                    self.add(text.into(), None, None)?;
                } else {
                    let mut nested = Worker {
                        job,
                        manifest: Manifest {
                            complete: false,
                            segments: vec![],
                            pages: vec![],
                            pdf: false,
                        },
                        pixels: self.pixels,
                        depth: self.depth + 1,
                        embedded_count: self.embedded_count,
                        embedded_bytes: self.embedded_bytes,
                    };
                    nested.inspect()?;
                    self.pixels = nested.pixels;
                    self.embedded_count = nested.embedded_count;
                    self.embedded_bytes = nested.embedded_bytes;
                    for segment in nested.manifest.segments {
                        self.add(segment.text, None, None)?;
                    }
                }
            }
            for index in 0..pages {
                let number = (index + 1).to_string();
                let text = tool(
                    "pdftotext",
                    &["-f", &number, "-l", &number, "-layout", path(&input)?, "-"],
                )?;
                self.add(String::from_utf8(text)?, Some(index), None)?;
                // Scan original embedded pixels as well as rendered pages. PDF
                // resampling can erase punctuation that identifies credentials.
                let extracted = self.job.join(format!("images-{index}"));
                std::fs::create_dir(&extracted)?;
                let prefix = extracted.join("image");
                tool(
                    "pdfimages",
                    &[
                        "-f",
                        &number,
                        "-l",
                        &number,
                        "-png",
                        path(&input)?,
                        path(&prefix)?,
                    ],
                )?;
                let mut entries =
                    std::fs::read_dir(&extracted)?.collect::<std::io::Result<Vec<_>>>()?;
                entries.sort_by_key(|e| e.file_name());
                if entries.len() > 16 {
                    bail!("embedded_image_limit");
                }
                for (n, entry) in entries.into_iter().enumerate() {
                    if !entry.file_type()?.is_file() {
                        bail!("unexpected_image_output");
                    }
                    let job = extracted.join(format!("scan-{n}"));
                    std::fs::create_dir(&job)?;
                    let mut raw_worker = Worker {
                        job,
                        manifest: Manifest {
                            complete: false,
                            segments: vec![],
                            pages: vec![],
                            pdf: false,
                        },
                        pixels: self.pixels,
                        depth: self.depth,
                        embedded_count: self.embedded_count,
                        embedded_bytes: self.embedded_bytes,
                    };
                    raw_worker.image(decode(&entry.path())?)?;
                    self.pixels = raw_worker.pixels;
                    for segment in raw_worker.manifest.segments {
                        self.add(segment.text, Some(index), None)?;
                    }
                }
                let render = self.job.join("render");
                tool(
                    "pdftoppm",
                    &[
                        "-f",
                        &number,
                        "-l",
                        &number,
                        "-singlefile",
                        "-scale-to",
                        "3000",
                        "-png",
                        path(&input)?,
                        path(&render)?,
                    ],
                )?;
                self.image(decode(&render.with_extension("png"))?)?;
            }
        } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
            let decoder =
                image::codecs::png::PngDecoder::new(BufReader::new(std::fs::File::open(&input)?))?;
            if decoder.is_apng()? {
                for (i, frame) in decoder.apng()?.into_frames().enumerate() {
                    if i >= 16 {
                        bail!("frame_limit");
                    }
                    self.image(DynamicImage::ImageRgba8(frame?.into_buffer()))?;
                }
            } else {
                self.image(decode(&input)?)?;
            }
        } else if data.starts_with(&[0xff, 0xd8, 0xff]) {
            self.image(decode(&input)?)?;
        } else {
            bail!("unsupported_attachment");
        }
        self.manifest.complete = true;
        std::fs::write(
            self.job.join("manifest.json"),
            serde_json::to_vec(&self.manifest)?,
        )?;
        Ok(())
    }
}
#[derive(Deserialize)]
struct Word {
    block_num: u32,
    par_num: u32,
    line_num: u32,
    left: u32,
    top: u32,
    width: u32,
    height: u32,
    text: String,
}
fn decode(path: &Path) -> Result<DynamicImage> {
    let mut reader = ImageReader::open(path)?.with_guessed_format()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(20_000);
    limits.max_image_height = Some(20_000);
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    Ok(reader.decode()?)
}
fn sanitize(job: &Path) -> Result<()> {
    let manifest: Manifest = serde_json::from_slice(&std::fs::read(job.join("manifest.json"))?)?;
    let selected: Vec<usize> =
        serde_json::from_slice(&std::fs::read(job.join("redactions.json"))?)?;
    let mut images = Vec::new();
    for (page, name) in manifest.pages.iter().enumerate() {
        let mut image = decode(&job.join(name))?.into_rgb8();
        for index in &selected {
            let segment = manifest.segments.get(*index).context("segment")?;
            if segment.page != Some(page) {
                continue;
            }
            let [x1, y1, x2, y2] = segment
                .bounds
                .unwrap_or([0, 0, image.width(), image.height()]);
            for y in y1.saturating_sub(8)..y2.saturating_add(8).min(image.height()) {
                for x in x1.saturating_sub(8)..x2.saturating_add(8).min(image.width()) {
                    image.put_pixel(x, y, image::Rgb([0, 0, 0]));
                }
            }
        }
        images.push(image);
    }
    if manifest.pdf {
        write_pdf(&images, &job.join("replacement"))?;
    } else if images.len() == 1 {
        images[0].save_with_format(job.join("replacement"), image::ImageFormat::Png)?;
    } else {
        bail!("animated_sanitization_unsupported");
    }
    Ok(())
}
fn write_pdf(images: &[image::RgbImage], output: &Path) -> Result<()> {
    let mut doc = Document::with_version("1.5");
    let pages_id = doc.new_object_id();
    let mut kids = Vec::new();
    for image in images {
        let image_id=doc.add_object(Stream::new(dictionary!{"Type"=>"XObject","Subtype"=>"Image","Width"=>image.width() as i64,"Height"=>image.height() as i64,"ColorSpace"=>"DeviceRGB","BitsPerComponent"=>8},image.as_raw().clone()));
        let width = f64::from(image.width());
        let height = f64::from(image.height());
        let content = doc.add_object(Stream::new(
            dictionary! {},
            format!("q {width} 0 0 {height} 0 0 cm /Im0 Do Q").into_bytes(),
        ));
        let resources = dictionary! {"XObject"=>dictionary!{"Im0"=>image_id}};
        let page=doc.add_object(dictionary!{"Type"=>"Page","Parent"=>pages_id,"MediaBox"=>vec![Object::Integer(0),Object::Integer(0),Object::Integer(image.width() as i64),Object::Integer(image.height() as i64)],"Resources"=>resources,"Contents"=>content});
        kids.push(Object::Reference(page));
    }
    doc.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {"Type"=>"Pages","Kids"=>kids,"Count"=>images.len() as i64}),
    );
    let catalog = doc.add_object(dictionary! {"Type"=>"Catalog","Pages"=>pages_id});
    doc.trailer.set("Root", catalog);
    doc.compress();
    doc.save(output)?;
    Ok(())
}
fn main() {
    // Limits are inherited by every native tool. The parent additionally enforces
    // a wall-clock deadline and kills the isolated PID namespace on cancellation.
    for (resource, value) in [
        (libc::RLIMIT_AS, 1536 * 1024 * 1024),
        (libc::RLIMIT_CPU, 90),
        (libc::RLIMIT_FSIZE, 64 * 1024 * 1024),
        (libc::RLIMIT_NOFILE, 128),
    ] {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        // SAFETY: limit points to a valid rlimit and these are Linux resource IDs.
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            std::process::exit(1);
        }
    }
    let result = (|| -> Result<Manifest> {
        let args: Vec<_> = std::env::args_os().collect();
        let job = PathBuf::from(args.get(1).context("job")?);
        #[cfg(feature = "test-fixtures")]
        if args.get(2).is_some_and(|s| s == "fixtures") {
            fixtures(&job)?;
            return Ok(Manifest {
                complete: true,
                segments: vec![],
                pages: vec![],
                pdf: false,
            });
        }
        #[cfg(feature = "test-fixtures")]
        if args.get(2).is_some_and(|s| s == "mock") {
            fixture_server()?;
            return Ok(Manifest {
                complete: true,
                segments: vec![],
                pages: vec![],
                pdf: false,
            });
        }
        if args.get(2).is_some_and(|s| s == "check") {
            tool("pdfinfo", &["-v"])?;
            tool("pdftotext", &["-v"])?;
            tool("pdftoppm", &["-v"])?;
            tool("pdfimages", &["-v"])?;
            // Poppler's pdfdetach reports version information with exit 99.
            let detach = Command::new("pdfdetach")
                .arg("-v")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            anyhow::ensure!(
                matches!(detach.code(), Some(0 | 99)),
                "pdfdetach_unavailable"
            );
            tool("qpdf", &["--version"])?;
            tool("exiftool", &["-ver"])?;
            tool("zbarimg", &["--version"])?;
            let languages = String::from_utf8(tool("tesseract", &["--list-langs"])?)?;
            anyhow::ensure!(
                languages.lines().any(|l| l.trim() == "eng"),
                "missing OCR language"
            );
            return Ok(Manifest {
                complete: true,
                segments: vec![],
                pages: vec![],
                pdf: false,
            });
        }
        if args.get(2).is_some_and(|s| s == "sanitize") {
            sanitize(&job)?;
            return Ok(Manifest {
                complete: true,
                segments: vec![],
                pages: vec![],
                pdf: false,
            });
        }
        let mut worker = Worker {
            job,
            manifest: Manifest {
                complete: false,
                segments: vec![],
                pages: vec![],
                pdf: false,
            },
            pixels: 0,
            depth: 0,
            embedded_count: 0,
            embedded_bytes: 0,
        };
        worker.inspect()?;
        Ok(worker.manifest)
    })();
    match result {
        Ok(m) => println!("{}", serde_json::to_string(&m).unwrap()),
        Err(_) => {
            println!("{{\"complete\":false,\"segments\":[]}}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "test-fixtures")]
fn fixtures(job: &Path) -> Result<()> {
    use base64::Engine;
    std::fs::create_dir_all(job)?;
    let key = format!("ghp_{}", "aB39".repeat(9));
    let image = image::RgbImage::from_pixel(100, 100, image::Rgb([255, 255, 255]));
    image.save(job.join("clean.png"))?;
    image.save(job.join("secret.png"))?;
    tool(
        "exiftool",
        &[
            "-overwrite_original",
            &format!("-Comment={key}"),
            path(&job.join("secret.png"))?,
        ],
    )?;
    write_pdf(std::slice::from_ref(&image), &job.join("clean.pdf"))?;
    let mut pdf = Document::load(job.join("clean.pdf"))?;
    let info = pdf.add_object(dictionary! {"Subject"=>Object::string_literal(key)});
    pdf.trailer.set("Info", info);
    pdf.save(job.join("secret.pdf"))?;
    for (name, file, mime) in [
        ("clean-png", "clean.png", "image/png"),
        ("secret-png", "secret.png", "image/png"),
        ("clean-pdf", "clean.pdf", "application/pdf"),
        ("secret-pdf", "secret.pdf", "application/pdf"),
    ] {
        let data = format!(
            "data:{mime};base64,{}",
            base64::engine::general_purpose::STANDARD.encode(std::fs::read(job.join(file))?)
        );
        let part = if mime == "application/pdf" {
            serde_json::json!({"type":"input_file","filename":"document.pdf","file_data":data})
        } else {
            serde_json::json!({"type":"input_image","image_url":data})
        };
        std::fs::write(
            job.join(format!("{name}.json")),
            serde_json::to_vec(
                &serde_json::json!({"model":"test","input":[{"role":"user","content":[part]}]}),
            )?,
        )?;
    }
    Ok(())
}

#[cfg(feature = "test-fixtures")]
fn fixture_server() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let router = axum::Router::new().route(
                "/v1/responses",
                axum::routing::post(|| async { axum::Json(serde_json::json!({"ok":true})) }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
            axum::serve(listener, router).await?;
            Ok::<(), anyhow::Error>(())
        })
}

export async function textImage(page, format, text, width = 960, height = 260) {
  const data = await page.evaluate(({ format, text, width, height }) => {
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext('2d');
    context.fillStyle = '#fff';
    context.fillRect(0, 0, width, height);
    context.fillStyle = '#111';
    context.font = 'bold 45px Arial, sans-serif';
    for (const [index, line] of text.entries()) context.fillText(line, 28, 78 + index * 62);
    return canvas.toDataURL(format, 0.94).split(',')[1];
  }, { format, text, width, height });
  return Buffer.from(data, 'base64');
}

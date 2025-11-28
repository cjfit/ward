// Script to create Ward icon variants with badges
// Run with: node create-ward-icons.js

const fs = require('fs');
const { createCanvas, loadImage } = require('canvas');
const path = require('path');

const sizes = [16, 32, 48, 128];
const iconsDir = path.join(__dirname, 'extension', 'icons');

async function createIconWithBadge(size, type) {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');

  // Load ward shield
  const shieldPath = path.join(iconsDir, 'ward-shield.png');
  const shield = await loadImage(shieldPath);

  // Draw shield
  ctx.drawImage(shield, 0, 0, size, size);

  // Calculate badge size and position (60% of icon size for diameter)
  const badgeSize = size * 0.6;
  const badgeRadius = badgeSize / 2;
  // Position badge in true bottom-right corner
  const badgeX = size - badgeRadius - size * 0.08;
  const badgeY = size - badgeRadius - size * 0.08;

  if (type === 'danger') {
    // Draw white circle with red border
    ctx.beginPath();
    ctx.arc(badgeX, badgeY, badgeRadius, 0, Math.PI * 2);
    ctx.fillStyle = 'white';
    ctx.fill();
    ctx.strokeStyle = '#E03C31';
    ctx.lineWidth = Math.max(2, size * 0.04);
    ctx.stroke();

    // Draw red exclamation mark
    ctx.fillStyle = '#DC2626';
    ctx.font = `bold ${size * 0.5}px Arial`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('!', badgeX, badgeY);
  } else if (type === 'safe') {
    // Draw green circle
    ctx.beginPath();
    ctx.arc(badgeX, badgeY, badgeRadius, 0, Math.PI * 2);
    ctx.fillStyle = '#10B981';
    ctx.fill();

    // Draw white checkmark
    ctx.strokeStyle = 'white';
    ctx.lineWidth = Math.max(2, size * 0.08);
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';

    // Checkmark path
    ctx.beginPath();
    ctx.moveTo(badgeX - badgeRadius * 0.5, badgeY);
    ctx.lineTo(badgeX - badgeRadius * 0.1, badgeY + badgeRadius * 0.4);
    ctx.lineTo(badgeX + badgeRadius * 0.5, badgeY - badgeRadius * 0.4);
    ctx.stroke();
  } else if (type === 'skipped') {
    // Draw orange circle
    ctx.beginPath();
    ctx.arc(badgeX, badgeY, badgeRadius, 0, Math.PI * 2);
    ctx.fillStyle = '#F97316';
    ctx.fill();

    // Draw white horizontal line (minus/skip symbol)
    ctx.strokeStyle = 'white';
    ctx.lineWidth = Math.max(2, size * 0.08);
    ctx.lineCap = 'round';

    // Horizontal line
    ctx.beginPath();
    ctx.moveTo(badgeX - badgeRadius * 0.5, badgeY);
    ctx.lineTo(badgeX + badgeRadius * 0.5, badgeY);
    ctx.stroke();
  }

  // Save file
  const filename = `icon-ward-${type}-${size}.png`;
  const filepath = path.join(iconsDir, filename);
  const buffer = canvas.toBuffer('image/png');
  fs.writeFileSync(filepath, buffer);
  console.log(`Created: ${filename}`);
}

async function main() {
  console.log('Creating Ward icon variants...');

  for (const size of sizes) {
    await createIconWithBadge(size, 'danger');
    await createIconWithBadge(size, 'safe');
    await createIconWithBadge(size, 'skipped');
  }

  console.log('\nAll icons created successfully!');
}

main().catch(err => {
  console.error('Error creating icons:', err);
  process.exit(1);
});

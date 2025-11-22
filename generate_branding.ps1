# DarkWin Branding Generator
# Author: viphacker.100
# Description: Generates wallpapers, logos, and icons for DarkWin OS

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

$BrandingDir = "DarkWin-Resources\Branding"
$WallpaperDir = "$BrandingDir\Wallpapers"
$LogoDir = "$BrandingDir\Logos"
$IconDir = "$BrandingDir\Icons"

# Create directories if they don't exist
foreach ($Dir in @($BrandingDir, $WallpaperDir, $LogoDir, $IconDir)) {
    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }
}

function New-MatrixWallpaper {
    param(
        [int]$Width = 1920,
        [int]$Height = 1080
    )
    
    $Bitmap = New-Object System.Drawing.Bitmap $Width, $Height
    $Graphics = [System.Drawing.Graphics]::FromImage($Bitmap)
    
    # Set background to black
    $Graphics.Clear([System.Drawing.Color]::Black)
    
    # Create Matrix effect
    $Font = New-Object System.Drawing.Font "Consolas", 14
    $Brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 0, 255, 0))
    
    # Add random Matrix characters
    $Random = New-Object System.Random
    $Chars = "01".ToCharArray()
    
    for ($i = 0; $i -lt 1000; $i++) {
        $X = $Random.Next(0, $Width)
        $Y = $Random.Next(0, $Height)
        $Char = $Chars[$Random.Next(0, $Chars.Length)]
        $Graphics.DrawString($Char, $Font, $Brush, $X, $Y)
    }
    
    # Add DarkWin text
    $TitleFont = New-Object System.Drawing.Font "Hack", 72, [System.Drawing.FontStyle]::Bold
    $TitleBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 0, 255, 0))
    $TitleText = "DARKWIN"
    $TitleSize = $Graphics.MeasureString($TitleText, $TitleFont)
    $TitleX = ($Width - $TitleSize.Width) / 2
    $TitleY = ($Height - $TitleSize.Height) / 2
    
    # Add glow effect
    for ($i = 0; $i -lt 5; $i++) {
        $GlowBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(50, 0, 255, 0))
        $Graphics.DrawString($TitleText, $TitleFont, $GlowBrush, ($TitleX - $i), ($TitleY - $i))
        $Graphics.DrawString($TitleText, $TitleFont, $GlowBrush, ($TitleX + $i), ($TitleY + $i))
    }
    
    $Graphics.DrawString($TitleText, $TitleFont, $TitleBrush, $TitleX, $TitleY)
    
    # Add tagline
    $TaglineFont = New-Object System.Drawing.Font "Hack", 24
    $TaglineText = "Powered by viphacker.100"
    $TaglineSize = $Graphics.MeasureString($TaglineText, $TaglineFont)
    $TaglineX = ($Width - $TaglineSize.Width) / 2
    $TaglineY = $TitleY + $TitleSize.Height + 20
    
    $Graphics.DrawString($TaglineText, $TaglineFont, $TitleBrush, $TaglineX, $TaglineY)
    
    # Save wallpaper
    $Bitmap.Save("$WallpaperDir\darkwin_matrix.png", [System.Drawing.Imaging.ImageFormat]::Png)
    $Graphics.Dispose()
    $Bitmap.Dispose()
}

function New-SkullLogo {
    param(
        [int]$Size = 512
    )
    
    $Bitmap = New-Object System.Drawing.Bitmap $Size, $Size
    $Graphics = [System.Drawing.Graphics]::FromImage($Bitmap)
    
    # Set background to transparent
    $Graphics.Clear([System.Drawing.Color]::Transparent)
    
    # Create skull shape
    $SkullPath = New-Object System.Drawing.Drawing2D.GraphicsPath
    
    # Skull outline
    $SkullPath.AddEllipse(($Size * 0.2), ($Size * 0.1), ($Size * 0.6), ($Size * 0.7))
    
    # Eye sockets
    $SkullPath.AddEllipse(($Size * 0.3), ($Size * 0.3), ($Size * 0.15), ($Size * 0.2))
    $SkullPath.AddEllipse(($Size * 0.55), ($Size * 0.3), ($Size * 0.15), ($Size * 0.2))
    
    # Nose
    $SkullPath.AddEllipse(($Size * 0.45), ($Size * 0.5), ($Size * 0.1), ($Size * 0.15))
    
    # Circuit pattern
    $CircuitPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 0, 255, 0)), 2
    
    # Add circuit lines
    for ($i = 0; $i -lt 10; $i++) {
        $X = $Random.Next(0, $Size)
        $Y = $Random.Next(0, $Size)
        $Graphics.DrawLine($CircuitPen, $X, $Y, ($X + 50), $Y)
        $Graphics.DrawLine($CircuitPen, $X, $Y, $X, ($Y + 50))
    }
    
    # Fill skull
    $SkullBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 0, 255, 0))
    $Graphics.FillPath($SkullBrush, $SkullPath)
    
    # Add glow effect
    $GlowBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(50, 0, 255, 0))
    for ($i = 0; $i -lt 5; $i++) {
        $Graphics.FillPath($GlowBrush, $SkullPath)
    }
    
    # Save logo
    $Bitmap.Save("$LogoDir\darkwin_skull.png", [System.Drawing.Imaging.ImageFormat]::Png)
    $Graphics.Dispose()
    $Bitmap.Dispose()
}

function New-SystemIcons {
    param(
        [int]$Size = 256
    )
    
    # Create different icon sizes
    $Sizes = @(16, 32, 48, 64, 128, 256)
    
    foreach ($IconSize in $Sizes) {
        $Bitmap = New-Object System.Drawing.Bitmap $IconSize, $IconSize
        $Graphics = [System.Drawing.Graphics]::FromImage($Bitmap)
        
        # Set background to transparent
        $Graphics.Clear([System.Drawing.Color]::Transparent)
        
        # Create icon design
        $IconPath = New-Object System.Drawing.Drawing2D.GraphicsPath
        $IconPath.AddEllipse(0, 0, $IconSize, $IconSize)
        
        # Fill with gradient
        $Brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
            (New-Object System.Drawing.Rectangle 0, 0, $IconSize, $IconSize),
            [System.Drawing.Color]::FromArgb(255, 0, 255, 0),
            [System.Drawing.Color]::FromArgb(255, 0, 128, 0),
            [System.Drawing.Drawing2D.LinearGradientMode]::Diagonal
        )
        
        $Graphics.FillPath($Brush, $IconPath)
        
        # Add "D" letter
        $Font = New-Object System.Drawing.Font "Hack", ($IconSize * 0.6), [System.Drawing.FontStyle]::Bold
        $TextBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
        $Text = "D"
        $TextSize = $Graphics.MeasureString($Text, $Font)
        $TextX = ($IconSize - $TextSize.Width) / 2
        $TextY = ($IconSize - $TextSize.Height) / 2
        
        $Graphics.DrawString($Text, $Font, $TextBrush, $TextX, $TextY)
        
        # Save icon
        $Bitmap.Save("$IconDir\darkwin_$($IconSize).png", [System.Drawing.Imaging.ImageFormat]::Png)
        $Graphics.Dispose()
        $Bitmap.Dispose()
    }
}

# Generate all branding assets
Write-Host "Generating DarkWin branding assets..."
New-MatrixWallpaper
New-SkullLogo
New-SystemIcons
Write-Host "Branding assets generated successfully!" 
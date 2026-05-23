package dev.rourunisen.tapauth.ui.scanner

import android.annotation.SuppressLint
import android.util.Log
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.zxing.*
import com.google.zxing.common.HybridBinarizer

class QRCodeAnalyzer(private val onQRCodeDetected: (String) -> Unit) : ImageAnalysis.Analyzer {

    private val reader =
        MultiFormatReader().apply {
            val hints =
                mapOf(
                    DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                    DecodeHintType.TRY_HARDER to true,
                )
            setHints(hints)
        }

    private var isProcessing = false
    private var frameCount = 0

    @SuppressLint("UnsafeOptInUsageError")
    override fun analyze(image: ImageProxy) {
        frameCount++
        if (frameCount % 30 == 0) {
            Log.d(TAG, "Analyzer running - processed $frameCount frames")
        }

        // Skip if already processing a detection
        if (isProcessing) {
            image.close()
            return
        }

        try {
            // Get image data from the Y plane (grayscale)
            val buffer = image.planes[0].buffer
            val data = ByteArray(buffer.remaining())
            buffer.get(data)

            val width = image.width
            val height = image.height
            val rowStride = image.planes[0].rowStride

            if (frameCount % 30 == 0) {
                Log.d(
                    TAG,
                    "Image: ${width}x${height}, rowStride=$rowStride, data size=${data.size}",
                )
            }

            val source =
                PlanarYUVLuminanceSource(data, rowStride, height, 0, 0, width, height, false)

            val bitmap = BinaryBitmap(HybridBinarizer(source))

            try {
                val result = reader.decodeWithState(bitmap)
                isProcessing = true
                Log.i(TAG, "✓ QR Code detected: ${result.text}")
                onQRCodeDetected(result.text)
            } catch (e: NotFoundException) {
                // No QR code in this frame - this is normal, don't log
            } catch (e: Exception) {
                Log.e(TAG, "Error decoding QR code", e)
            } finally {
                reader.reset()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing image", e)
        } finally {
            image.close()
        }
    }

    companion object {
        private const val TAG = "QRCodeAnalyzer"
    }
}

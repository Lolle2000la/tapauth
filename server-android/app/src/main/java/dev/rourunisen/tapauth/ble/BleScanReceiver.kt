package dev.rourunisen.tapauth.ble

import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanResult
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import java.lang.ref.WeakReference

class BleScanReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BleScanReceiver"
        @Volatile var serviceRef: WeakReference<BleGattService>? = null
    }

    override fun onReceive(context: Context, intent: Intent) {
        val callbackType = intent.getIntExtra(BluetoothLeScanner.EXTRA_CALLBACK_TYPE, -1)
        if (callbackType == -1) return

        val scanResults: List<ScanResult>? =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableArrayListExtra(
                    BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT,
                    ScanResult::class.java,
                )
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableArrayListExtra(BluetoothLeScanner.EXTRA_LIST_SCAN_RESULT)
            }

        scanResults?.forEach { result ->
            val serviceData =
                result.scanRecord?.getServiceData(ParcelUuid(BleGattService.SERVICE_UUID))
            if (serviceData?.size == 10) {
                Log.d(TAG, "Forwarding scan result to BleGattService")
                val service = serviceRef?.get()
                if (service != null) {
                    service.handleScanResult(result.device, serviceData, result.rssi)
                } else {
                    val config = dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)
                    if (!config.bleRunning) {
                        Log.d(TAG, "BLE service disabled by user, ignoring scan result")
                        return
                    }
                    val serviceIntent =
                        Intent(context, BleGattService::class.java).apply {
                            action = BleGattService.ACTION_SCAN_RESULT
                            putExtra(BleGattService.EXTRA_DEVICE, result.device)
                            putExtra(BleGattService.EXTRA_TEMPORAL_ID, serviceData)
                            putExtra(BleGattService.EXTRA_RSSI, result.rssi)
                        }
                    try {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            context.startForegroundService(serviceIntent)
                        } else {
                            context.startService(serviceIntent)
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to start BleGattService from background", e)
                    }
                }
            }
        }
    }
}

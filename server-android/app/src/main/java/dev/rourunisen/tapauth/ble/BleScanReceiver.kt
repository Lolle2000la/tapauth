package dev.rourunisen.tapauth.ble

import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanResult
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.ParcelUuid
import android.util.Log

class BleScanReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "BleScanReceiver"
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
                val serviceIntent =
                    Intent(context, BleGattService::class.java).apply {
                        action = BleGattService.ACTION_SCAN_RESULT
                        putExtra(BleGattService.EXTRA_DEVICE, result.device)
                        putExtra(BleGattService.EXTRA_TEMPORAL_ID, serviceData)
                        putExtra(BleGattService.EXTRA_RSSI, result.rssi)
                    }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent)
                } else {
                    context.startService(serviceIntent)
                }
            }
        }
    }
}

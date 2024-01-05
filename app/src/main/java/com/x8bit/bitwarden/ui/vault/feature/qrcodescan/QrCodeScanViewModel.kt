package com.x8bit.bitwarden.ui.vault.feature.qrcodescan

import com.x8bit.bitwarden.data.vault.repository.VaultRepository
import com.x8bit.bitwarden.ui.platform.base.BaseViewModel
import com.x8bit.bitwarden.ui.platform.base.util.Text
import com.x8bit.bitwarden.ui.platform.base.util.asText
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

/**
 * Handles [QrCodeScanAction],
 * and launches [QrCodeScanEvent] for the [QrCodeScanScreen].
 */
@HiltViewModel
class QrCodeScanViewModel @Inject constructor(
    private val vaultRepository: VaultRepository,
) : BaseViewModel<Unit, QrCodeScanEvent, QrCodeScanAction>(
    initialState = Unit,
) {
    override fun handleAction(action: QrCodeScanAction) {
        when (action) {
            is QrCodeScanAction.CloseClick -> handleCloseClick()
            is QrCodeScanAction.ManualEntryTextClick -> handleManualEntryTextClick()
            is QrCodeScanAction.QrCodeScanReceive -> handleQrCodeScanReceive(action)
            is QrCodeScanAction.CameraSetupErrorReceive -> handleCameraErrorReceive(action)
        }
    }

    private fun handleCloseClick() {
        sendEvent(
            QrCodeScanEvent.NavigateBack,
        )
    }

    private fun handleManualEntryTextClick() {
        // TODO: Implement Manual Entry Screen (BIT-1114)
        sendEvent(
            QrCodeScanEvent.ShowToast(
                message = "Not yet implemented.".asText(),
            ),
        )
    }

    private fun handleQrCodeScanReceive(action: QrCodeScanAction.QrCodeScanReceive) {
        vaultRepository.emitTotpCode(action.qrCode)
        sendEvent(QrCodeScanEvent.NavigateBack)
    }

    private fun handleCameraErrorReceive(
        action: QrCodeScanAction.CameraSetupErrorReceive,
    ) {
        // TODO: Implement Manual Entry Screen (BIT-1114)
        sendEvent(
            QrCodeScanEvent.ShowToast(
                message = "Not yet implemented.".asText(),
            ),
        )
    }
}

/**
 * Models events for the [QrCodeScanScreen].
 */
sealed class QrCodeScanEvent {

    /**
     * Navigate back.
     */
    data object NavigateBack : QrCodeScanEvent()

    /**
     * Show a toast with the given [message].
     */
    data class ShowToast(val message: Text) : QrCodeScanEvent()
}

/**
 * Models actions for the [QrCodeScanScreen].
 */
sealed class QrCodeScanAction {

    /**
     * User clicked close.
     */
    data object CloseClick : QrCodeScanAction()

    /**
     * The user has scanned a QR code.
     */
    data class QrCodeScanReceive(val qrCode: String) : QrCodeScanAction()

    /**
     * The text to switch to manual entry is clicked.
     */
    data object ManualEntryTextClick : QrCodeScanAction()

    /**
     * The Camera is unable to be setup.
     */
    data object CameraSetupErrorReceive : QrCodeScanAction()
}
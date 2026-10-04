package app.cipher.messenger.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import app.cipher.messenger.data.AppViewModel
import app.cipher.messenger.data.UiState
import app.cipher.messenger.ui.components.Banner
import app.cipher.messenger.ui.components.IconAction
import app.cipher.messenger.ui.components.PrimaryButton
import app.cipher.messenger.ui.components.QrCode
import app.cipher.messenger.ui.components.SecureDialog
import app.cipher.messenger.ui.components.TrustBadge
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import uniffi.cipher_ffi.TrustStateFfi

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerifyContactScreen(
    account: String,
    state: UiState,
    vm: AppViewModel,
    myQr: String?,
    scanned: String?,
    onScan: () -> Unit,
    onBack: () -> Unit
) {
    val contact = state.contacts.firstOrNull { it.accountId == account }
    val safety by produceState<String?>(null, account, contact?.trust) {
        value =
            runCatching { vm.host.call { it.getSafetyNumber(account) } }.getOrNull()
    }
    var confirmVerify by remember { mutableStateOf(false) }
    var confirmAccept by remember { mutableStateOf(false) }
    var showMine by remember { mutableStateOf(false) }

    LaunchedEffect(scanned) {
        if (scanned != null) vm.verifyContactByQr(account, scanned)
    }

    Scaffold(topBar = {
        TopAppBar(title = {
            Text("Verify ${contact?.name ?: "contact"}")
        }, navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) })
    }) { pad ->
        Column(
            Modifier.fillMaxSize().padding(pad).verticalScroll(rememberScrollState()).padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            contact?.let { TrustBadge(it.trust) }
            Spacer(Modifier.height(12.dp))
            if (contact?.trust == TrustStateFfi.IDENTITY_CHANGED) {
                Banner(
                    "${contact.name}'s identity changed. This can happen if they reinstalled Cipher or got a new phone " +
                        "— or if someone is intercepting. " +
                        "Compare the new safety number in person or over a trusted channel before accepting.",
                    error = true,
                )
            }
            Text("Safety number", style = MaterialTheme.typography.titleMedium)
            Text(
                "If this matches what ${contact?.name ?: "your contact"} sees on their phone, nobody is in the middle of your conversation.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(12.dp))
            Surface(
                shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
                color = MaterialTheme.colorScheme.surfaceContainer,
                modifier = Modifier.fillMaxWidth()
            ) {
                val groups = (safety ?: "").split(" ").filter { it.isNotEmpty() }
                Column(
                    Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    groups.chunked(4).forEach { row ->
                        Text(row.joinToString("   "), fontFamily = FontFamily.Monospace, fontSize = 18.sp, fontWeight = FontWeight.Medium)
                    }
                    if (groups.isEmpty()) Text("…")
                }
            }
            Spacer(Modifier.height(16.dp))
            OutlinedButton(onClick = onScan, modifier = Modifier.fillMaxWidth()) { Text("Scan their code to verify") }
            OutlinedButton(onClick = {
                showMine = !showMine
            }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text(if (showMine) "Hide my code" else "Show my code") }
            if (showMine && myQr != null) {
                Spacer(Modifier.height(12.dp))
                QrCode(myQr, 220.dp)
            }
            Spacer(Modifier.height(16.dp))
            when (contact?.trust) {
                TrustStateFfi.IDENTITY_CHANGED -> PrimaryButton("I verified — accept the new identity") { confirmAccept = true }
                TrustStateFfi.UNVERIFIED -> PrimaryButton("Mark as verified") { confirmVerify = true }
                else -> Text("You verified this contact.", color = MaterialTheme.colorScheme.tertiary)
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "Verification is independent of the server: the code on their phone and the safety number are computed on the two devices.",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
    if (confirmVerify) {
        SecureDialog(
            onDismiss = { confirmVerify = false },
            title = "Mark as verified?",
            text = { Text("Only do this if you compared the numbers (or scanned their code) with ${contact?.name}.") },
            confirmLabel = "Mark verified",
            onConfirm = { vm.markVerified(account) },
        )
    }
    if (confirmAccept) {
        SecureDialog(
            onDismiss = { confirmAccept = false },
            title = "Accept new identity?",
            text = { Text("Messages to ${contact?.name} will use their new identity. You'll need to verify it again.") },
            confirmLabel = "Accept",
            destructive = true,
            onConfirm = { vm.acknowledgeIdentityChange(account) },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScanScreen(onResult: (String) -> Unit, onBack: () -> Unit) {
    val ctx = LocalContext.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        )
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    LaunchedEffect(Unit) { if (!granted) launcher.launch(Manifest.permission.CAMERA) }
    Scaffold(topBar = {
        TopAppBar(title = { Text("Scan code") }, navigationIcon = { IconAction(Icons.AutoMirrored.Filled.ArrowBack, "Back", onBack) })
    }) { pad ->
        Box(Modifier.fillMaxSize().padding(pad), contentAlignment = Alignment.Center) {
            if (granted) {
                CameraPreview(
                    onResult
                )
            } else {
                Text("Camera permission is needed to scan a code.", modifier = Modifier.padding(24.dp), textAlign = TextAlign.Center)
            }
        }
    }
}

@Composable
private fun CameraPreview(onResult: (String) -> Unit) {
    val ctx = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    var done by remember { mutableStateOf(false) }
    DisposableEffect(Unit) { onDispose { executor.shutdown() } }
    AndroidView(
        modifier = Modifier.fillMaxSize(),
        factory = { c ->
            val view = PreviewView(c)
            val future = ProcessCameraProvider.getInstance(c)
            future.addListener({
                val provider = future.get()
                val preview = Preview.Builder().build().also { it.setSurfaceProvider(view.surfaceProvider) }
                val reader = MultiFormatReader().apply {
                    setHints(
                        mapOf(
                            DecodeHintType.POSSIBLE_FORMATS to listOf(com.google.zxing.BarcodeFormat.QR_CODE)
                        )
                    )
                }
                val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
                analysis.setAnalyzer(executor) { img ->
                    try {
                        if (!done) {
                            val plane = img.planes[0]
                            val buf = plane.buffer
                            val data = ByteArray(buf.remaining()).also { buf.get(it) }
                            val src = PlanarYUVLuminanceSource(data, plane.rowStride, img.height, 0, 0, img.width, img.height, false)
                            val text = runCatching { reader.decodeWithState(BinaryBitmap(HybridBinarizer(src))).text }.getOrNull()
                            if (text != null) {
                                done = true
                                ContextCompat.getMainExecutor(ctx).execute { onResult(text) }
                            }
                        }
                    } finally {
                        img.close()
                    }
                }
                provider.unbindAll()
                provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            }, ContextCompat.getMainExecutor(c))
            view
        },
    )
}

"""
End-to-end integration test validating the entire live pipeline:
DATA -> PREPROCESS -> PREDICT -> HASH -> ENCRYPT -> BLOCKCHAIN -> VERIFY -> DISPLAY
"""

import pytest
import numpy as np
from src.data_loader import DataLoader
from src.preprocessing import PreprocessingPipeline
from src.feature_selection import FeatureSelector
from src.models import ModelBenchmarkSuite
from src.streaming import LiveStreamSimulator


def test_complete_end_to_end_pipeline():
    # 1. DATA
    loader = DataLoader()
    df = loader.load_raw_data(sample_mode="demo")
    assert len(df) > 0

    # 2. PREPROCESS & MI SELECTION
    pipeline = PreprocessingPipeline()
    split = pipeline.prepare_train_test_split(df, test_size=0.2)
    selector = FeatureSelector()
    mi = selector.compute_mutual_information(
        split["X_train"], split["y_train_bin"], split["y_train_multi"], split["feature_names"]
    )
    X_train_top, names, _ = selector.select_top_k(split["X_train"], split["feature_names"], mi, top_k=20)
    X_test_top, _, _ = selector.select_top_k(split["X_test"], split["feature_names"], mi, top_k=20)

    # 3. TRAIN INTRUSION DETECTION MODEL
    suite = ModelBenchmarkSuite()
    train_res = suite.train_and_eval_binary(
        "decision_tree", X_train_top, split["y_train_bin"], X_test_top, split["y_test_bin"]
    )
    model = train_res["model"]

    # 4. INITIALIZE LIVE STREAM SIMULATOR
    streamer = LiveStreamSimulator(
        raw_df=df,
        pipeline=pipeline,
        feature_selector=selector,
        model=model,
        ranking_data=mi,
        top_k=20
    )

    # 5. PROCESS 5 STREAMING EVENTS
    events = []
    for _ in range(5):
        evt = streamer.process_next_event()
        events.append(evt)

    assert len(events) == 5
    for evt in events:
        # Check required fields
        assert "event_number" in evt
        assert "prediction" in evt
        assert "confidence" in evt
        assert "risk_score" in evt
        assert "risk_tier" in evt
        assert "sha256_hash" in evt
        assert "blockchain_tx" in evt
        assert "block_number" in evt
        assert "authorization" in evt
        assert "integrity" in evt
        assert evt["integrity"] == "INTEGRITY_VERIFIED"
        assert evt["total_latency_ms"] > 0.0


def test_offline_artifact_end_to_end_flow():
    """
    Mandatory Section 56 Test:
    load artifact -> load one sample -> preprocess -> predict -> generate event ->
    hash -> encrypt -> blockchain -> verify -> return result.
    NO TRAINING PERFORMED.
    """
    import os, time, json, joblib, torch, pandas as pd
    from src.deep_models import HybridIDSNet
    from src.crypto import CryptographicEngine
    from src.blockchain import BlockchainEngine

    # 1. LOAD ARTIFACTS
    assert os.path.exists("artifacts/models/production_model/production_model.pt")
    assert os.path.exists("artifacts/preprocessing/preprocessor.joblib")
    assert os.path.exists("artifacts/features/selected_features.json")

    preprocessor = joblib.load("artifacts/preprocessing/preprocessor.joblib")
    with open("artifacts/features/selected_features.json", "r") as f:
        selected_features = json.load(f)["top_20"]
    with open("artifacts/models/production_model/model_config.json", "r") as f:
        model_cfg = json.load(f)

    device = torch.device("cpu")
    model = HybridIDSNet(
        input_dim=len(selected_features),
        num_classes=2,
        conv_filters=model_cfg.get("conv_filters", 64),
        lstm_hidden_dim=model_cfg.get("lstm_hidden", 64),
        attention_heads=model_cfg.get("attention_heads", 4),
        dense_dim=model_cfg.get("dense_dim", 128),
        dropout=model_cfg.get("dropout", 0.25)
    ).to(device)
    model.load_state_dict(torch.load("artifacts/models/production_model/production_model.pt", map_location=device))
    model.eval()

    # 2. LOAD ONE SAMPLE
    demo_df = pd.read_csv("artifacts/demo/live_samples.csv")
    sample_record = demo_df.iloc[0].to_dict()

    # 3. PREPROCESS (using saved pipeline with zero fitting)
    scaled_row = preprocessor.transform_single_record(sample_record)
    if hasattr(scaled_row, "columns"):
        X_vec = scaled_row[selected_features].values
    else:
        col_idx = [preprocessor.feature_names.index(f) for f in selected_features if f in preprocessor.feature_names]
        X_vec = scaled_row[:, col_idx]

    # 4. PREDICT
    X_tensor = torch.tensor(X_vec, dtype=torch.float32).to(device)
    with torch.no_grad():
        logits = model(X_tensor)
        prob = float(torch.sigmoid(logits.squeeze()).cpu().numpy())
    pred_bin = 1 if prob >= 0.5 else 0
    conf = prob * 100.0 if pred_bin == 1 else (1.0 - prob) * 100.0

    # 5. GENERATE SECURITY EVENT
    event_id = f"0xTEST_EVENT_{int(time.time())}"
    crypto = CryptographicEngine()
    blockchain = BlockchainEngine()

    # 6. HASH WITH SHA-256
    payload_hash = crypto.compute_sha256(sample_record)
    assert len(payload_hash) == 64

    # 7. ENCRYPT
    enc_blob = crypto.encrypt_payload(sample_record)
    assert len(enc_blob) > 0

    # 8. BLOCKCHAIN ANCHOR
    tx = blockchain.submit_security_event_tx(
        event_id=event_id,
        device_hash="0xTEST_DEVICE_01",
        prediction=pred_bin,
        attack_type=str(sample_record.get("Attack_type", "Normal")),
        confidence=conf,
        payload_hash=payload_hash,
        model_hash="0xMODEL_HASH_VAL",
        policy_hash="0xPOLICY_HASH_VAL"
    )
    assert tx["status"] in ["SUCCESS", "CONFIRMED"]
    assert "0x" in tx["tx_hash"]

    # 9. VERIFY
    tamper_audit = blockchain.verify_tamper_evidence(event_id, payload_hash)
    assert tamper_audit["verdict"] == "INTEGRITY_VERIFIED"
    assert tamper_audit["integrity_verified"] is True

    # 10. RETURN RESULT
    assert pred_bin in [0, 1]


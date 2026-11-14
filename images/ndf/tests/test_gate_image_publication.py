import hashlib, json
import pytest
from scripts.bind_verification_evidence import create_verification_evidence, write_report
from scripts.gate_image_publication import PublicationGateError, verify_publication_candidate

DIGEST="sha256:"+"a"*64
REPOSITORY="ghcr.io/ndftechlabs/dalali"
IMAGE_ID="dalali-v16"
SOURCE_SHA="b"*40
CANDIDATE_REF=f"{REPOSITORY}:candidate-12345-1"
PUBLICATION_REF=f"{REPOSITORY}:v16-{SOURCE_SHA}"

def write_json(path,value):
    path.write_text(json.dumps(value,sort_keys=True)+"\n",encoding="utf-8")

@pytest.fixture
def candidate(tmp_path):
    lock=b'{"lock_version":2}\n'
    files={
      "dalali-v16.lock-v2.json":lock,"apps.json":b'[]\n',
      "build-metadata.json":json.dumps({"image":{"id":IMAGE_ID,"repository":REPOSITORY},
        "framework":{"version":"16.0.0"},"lock":{"sha256":hashlib.sha256(lock).hexdigest()}}).encode()+b"\n",
      "buildx-metadata.json":json.dumps({"containerimage.digest":DIGEST}).encode()+b"\n",
      "build-inventory.json":b'{"schema_version":"1.0"}\n',
      "build-evidence.json":json.dumps({"status":"bound","image_digest":DIGEST,
        "lock_sha256":hashlib.sha256(lock).hexdigest()}).encode()+b"\n",
      "source-provenance.json":b'{"schema_version":"1.0"}\n',
      "source-provenance-verification.json":b'{"status":"passed"}\n',
      "source-tree-verification-post-cleanup.json":b'{"status":"passed"}\n',
      "source-tree-verification-runtime.json":b'{"status":"passed"}\n',
      "image-composition-verification.json":b'{"status":"passed"}\n'}
    for name,raw in files.items(): (tmp_path/name).write_bytes(raw)
    logical={"lock_v2":"dalali-v16.lock-v2.json","apps_json":"apps.json",
      "build_metadata":"build-metadata.json","buildx_metadata":"buildx-metadata.json",
      "build_inventory":"build-inventory.json","build_evidence":"build-evidence.json",
      "source_provenance":"source-provenance.json",
      "source_provenance_verification":"source-provenance-verification.json",
      "source_tree_post_cleanup":"source-tree-verification-post-cleanup.json",
      "source_tree_runtime":"source-tree-verification-runtime.json",
      "image_composition_verification":"image-composition-verification.json"}
    artifacts={key:('lock-v2.json' if key=='lock_v2' else filename,(tmp_path/filename).read_bytes()) for key,filename in logical.items()}
    statuses={key:"passed" for key in ("source_provenance_verification","source_tree_post_cleanup","source_tree_runtime","image_composition_verification")}
    evidence=create_verification_evidence(image_reference=CANDIDATE_REF,image_repository=REPOSITORY,
      image_id=IMAGE_ID,image_digest=DIGEST,lock_bytes=lock,artifacts=artifacts,statuses=statuses)
    write_report(evidence,tmp_path/"image-verification-evidence.json")
    write_json(tmp_path/"build-result.json",{"image_id":IMAGE_ID,"repository":REPOSITORY,
      "tags":["candidate-12345-1"],"image_refs":[CANDIDATE_REF],"output":"registry","pushed":True,"digest":DIGEST})
    write_json(tmp_path/"image-validation.json",{"status":"passed","image":CANDIDATE_REF,
      "image_id":IMAGE_ID,"image_digest":DIGEST,"verification_evidence":evidence})
    return tmp_path

def run_gate(path,**overrides):
    args={"build_output_dir":path,"image_id":IMAGE_ID,"source_sha":SOURCE_SHA,
      "framework_major":"16","candidate_image_ref":CANDIDATE_REF,"publication_image_ref":PUBLICATION_REF}
    args.update(overrides)
    return verify_publication_candidate(**args)

def test_accepts_fully_verified_staging_candidate(candidate):
    report=run_gate(candidate)
    assert report["status"]=="ready"
    assert report["image"]["digest"]==DIGEST
    assert report["image"]["publication_reference"]==PUBLICATION_REF

def test_rejects_local_build_not_pushed_to_staging(candidate):
    result=json.loads((candidate/"build-result.json").read_text())
    result.update(pushed=False,output="local")
    write_json(candidate/"build-result.json",result)
    with pytest.raises(PublicationGateError,match="staging registry"): run_gate(candidate)

def test_rejects_buildx_and_build_result_digest_mismatch(candidate):
    write_json(candidate/"buildx-metadata.json",{"containerimage.digest":"sha256:"+"c"*64})
    with pytest.raises(PublicationGateError,match="digests differ"): run_gate(candidate)

def test_rejects_failed_image_validation(candidate):
    report=json.loads((candidate/"image-validation.json").read_text())
    report["status"]="failed"
    write_json(candidate/"image-validation.json",report)
    with pytest.raises(PublicationGateError,match="not passed"): run_gate(candidate)

def test_rejects_tampered_verification_evidence(candidate):
    (candidate/"source-provenance.json").write_text('{"tampered":true}\n')
    with pytest.raises(PublicationGateError,match="evidence failed"): run_gate(candidate)

def test_rejects_failed_independent_report(candidate):
    (candidate/"source-tree-verification-runtime.json").write_text('{"status":"failed"}\n')
    with pytest.raises(PublicationGateError,match="did not pass"): run_gate(candidate)

def test_rejects_wrong_publication_source_tag(candidate):
    with pytest.raises(PublicationGateError,match="does not match"):
        run_gate(candidate,publication_image_ref=f"{REPOSITORY}:latest")

def test_rejects_non_staging_candidate_reference(candidate):
    with pytest.raises(PublicationGateError,match="staging tag"):
        run_gate(candidate,candidate_image_ref=f"{REPOSITORY}:v16-{SOURCE_SHA}")

def test_rejects_missing_required_evidence(candidate):
    (candidate/"image-composition-verification.json").unlink()
    with pytest.raises(PublicationGateError,match="missing"): run_gate(candidate)

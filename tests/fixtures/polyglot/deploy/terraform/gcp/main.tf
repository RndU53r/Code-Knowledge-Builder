# GCP analytics export (fixture; never apply)
resource "google_storage_bucket" "exports" {
  name     = "shop-exports-fixture"
  location = "EU"
}

resource "google_storage_bucket_iam_member" "exports_public" {
  bucket = google_storage_bucket.exports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_compute_firewall" "admin" {
  name          = "allow-admin"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

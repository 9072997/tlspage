package tlspage

import "testing"

func TestHostname(t *testing.T) {
	type args struct {
		privKeyPEM string
		origin     string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "valid key and origin",
			args: args{
				privKeyPEM: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSLUS/L0btj6MI4CT
LOk1uUMvg3VF66Ysv92oy1Qa196hRANCAAT8wRaBqWXecdg91c9OFWwWghXcGs3W
XQS1FcOMiCzxP8w2/23AJuqDi7lkgp7zEdxtwIGk89QBGGF0s30Qo6Zs
-----END PRIVATE KEY-----`,
				origin: "example.com",
			},
			want:    "9b7d8f4b4f45183149c1b666d08d1f8c.bfcd0704a087908e509c39b1c2b98cc5.example.com",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Hostname(tt.args.privKeyPEM, tt.args.origin)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hostname() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Hostname() = %v, want %v", got, tt.want)
			}
		})
	}
}

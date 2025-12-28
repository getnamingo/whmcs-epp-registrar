<div class="card">
    <div class="card-body">
        <h3 class="card-title">DNSSEC</h3>
        <p>Manage DS records to enable DNSSEC for this domain.</p>

{if $error}
        <div class="alert alert-warning">
            <i class='fas fa-exclamation-circle fa-fw'></i> {$error}
        </div>
{else}
    {if $DSRecords eq 'YES'}
    <h3 class="card-title">DS records</h3>
    <div class="table-responsive">
        <table class="table table-sm table-striped align-middle">
            <thead>
            <tr>
                <th>Key tag</th>
                <th>Alg</th>
                <th>Digest type</th>
                <th>Digest</th>
                <th class="text-center">Action</th>
            </tr>
            </thead>
            <tbody>
            {foreach $DSRecordslist as $item}
                <tr>
                    <td>{$item.keyTag}</td>
                    <td>{$item.alg}</td>
                    <td>{$item.digestType}</td>
                    <td class="text-break" style="max-width: 300px;">
                        {$item.digest}
                    </td>
                    <td class="text-center">
                        <form method="post" action="clientarea.php" class="d-inline">
                            <input type="hidden" name="action" value="domaindetails" />
                            <input type="hidden" name="id" value="{$domainid}" />
                            <input type="hidden" name="modop" value="custom" />
                            <input type="hidden" name="a" value="manageDNSSECDSRecords" />
                            <input type="hidden" name="command" value="secDNSrem" />

                            <input type="hidden" name="keyTag" value="{$item.keyTag}" />
                            <input type="hidden" name="alg" value="{$item.alg}" />
                            <input type="hidden" name="digestType" value="{$item.digestType}" />
                            <input type="hidden" name="digest" value="{$item.digest}" />

                            <button type="submit" class="btn btn-sm btn-danger">
                                Remove
                            </button>
                        </form>
                    </td>
                </tr>
            {/foreach}
            </tbody>
        </table>
    </div>
    {else}
        <div class="alert alert-info">
            <i class='fas fa-info-circle fa-fw'></i> {$DSRecords}
        </div>
    {/if}
{/if}
    </div>
</div>

<div class="card">
    <div class="card-body">
        <form method="post" action="clientarea.php">
            <input type="hidden" name="action" value="domaindetails" />
            <input type="hidden" name="id" value="{$domainid}" />
            <input type="hidden" name="modop" value="custom" />
            <input type="hidden" name="a" value="manageDNSSECDSRecords" />
            <input type="hidden" name="command" value="secDNSadd" />

            <h3 class="card-title">Create a DS Record</h3>

            <div class="form-group row">
                <label for="keytag1" class="col-md-4 col-form-label">Key tag</label>
                <div class="col-md-6">
                    <input name="keyTag" type="text" maxlength="65535" class="form-control" id="keytag1" data-supported="True" data-required="True" data-previousvalue="" />
                </div>
            </div>
            <div class="form-group row">
                <label for="alg1" class="col-md-4 col-form-label">Algorithm</label>
                <div class="col-md-6">
                    <select name="alg" data-supported="True" class="form-control" id="alg1" data-required="True" data-previousvalue="">
                        <option value="8">RSA/SHA-256 (8)</option>
                        <option value="13">ECDSA Curve P-256 with SHA-256 (13)</option>
                        <option value="14">ECDSA Curve P-384 with SHA-384 (14)</option>
                        <option value="15">Ed25519 (15)</option>
                        <option value="16">Ed448 (16)</option>
                    </select>
                </div>
            </div>
            <div class="form-group row">
                <label for="digestType" class="col-md-4 col-form-label">Digest type</label>
                <div class="col-md-6">
                    <select name="digestType" class="form-control" id="digestType" data-supported="True" data-required="True" data-previousvalue="">
                        <option value="2">SHA-256 (2)</option>
                        <option value="4">SHA-384 (4)</option>
                    </select>
                </div>
            </div>
            <div class="form-group row">
                <label for="digest1" class="col-md-4 col-form-label">Digest</label>
                <div class="col-md-6">
                    <textarea name="digest" class="form-control" rows="2" data-supported="True" id="digest1" data-required="True" data-previousvalue=""></textarea>
                </div>
            </div>

            <div class="text-center">
                <button type="submit" class="btn btn-primary">
                    Create DS Record
                </button>
            </div>

        </form>
    </div>
</div>
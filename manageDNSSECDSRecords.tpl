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
        {foreach $DSRecordslist as $item}
        <form method="post" action="clientarea.php">    
            <input type="hidden" name="action" value="domaindetails" />
            <input type="hidden" name="id" value="{$domainid}" />
            <input type="hidden" name="modop" value="custom" />
            <input type="hidden" name="a" value="manageDNSSECDSRecords" />
            <input type="hidden" name="command" value="secDNSrem" />

            <h3 class="card-title">DS records:</h3>

            <div class="form-group row">
                <label for="keytag1a" class="col-md-4 col-form-label">Key tag</label>
                <div class="col-md-6">
                    <input name="keyTag" type="text" maxlength="65535" class="form-control" id="keytag1a" data-supported="True" data-required="True" value="{$item.keyTag}" />
                </div>
            </div>
            <div class="form-group row">
                <label for="alg1a" class="col-md-4 col-form-label">Algorithm</label>
                <div class="col-md-6">
                    <input name="alg" class="form-control" id="alg1a" data-supported="True" data-required="True" value="{$item.alg}">
                </div>
            </div>
            <div class="form-group row">
                <label for="digestType1" class="col-md-4 col-form-label">Digest type</label>
                <div class="col-md-6">
                    <input name="digestType" class="form-control" id="digestType1" data-supported="True" data-required="True" value="{$item.digestType}">
                </div>
            </div>
            <div class="form-group row">
                <label for="digest1a" class="col-md-4 col-form-label">Digest</label>
                <div class="col-md-6">
                    <textarea name="digest" class="form-control" rows="2" data-supported="True" id="digest1a" data-required="True">{$item.digest}</textarea>
                </div>
            </div>

            <div class="text-center">
                <button type="submit" class="btn btn-primary">
                    Remove DS Record
                </button>
            </div>

        </form>
        {/foreach}
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
                        <option value="1">1</option>
                        <option value="2">2</option>
                        <option value="3">3</option>
                        <option value="4">4</option>
                        <option value="5">5</option>
                        <option value="6">6</option>
                        <option value="7">7</option>
                        <option value="8">8</option>
                        <option value="10">10</option>
                        <option value="12">12</option>
                        <option value="13">13</option>
                        <option value="253">253</option>
                        <option value="254">254</option>
                    </select>
                </div>
            </div>
            <div class="form-group row">
                <label for="digestType" class="col-md-4 col-form-label">Digest type</label>
                <div class="col-md-6">
                    <select name="digestType" class="form-control" id="digestType" data-supported="True" data-required="True" data-previousvalue="">
                        <option value="1">1</option>
                        <option value="2">2</option>
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
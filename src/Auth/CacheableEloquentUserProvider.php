<?php
namespace HobbIoT\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Support\Str;

class CacheableEloquentUserProvider extends EloquentUserProvider {

	/**
	 * Retrieve a user by their unique identifier.
	 *  - override -
	 *  with using cache.
	 *
	 * @param  mixed  $identifier
	 * @return \Illuminate\Contracts\Auth\Authenticatable|null
	 */
	public function retrieveById($identifier)
	{
		return cache()->remember($this->getModel() . '_By_Id_' . $identifier, 60,
			function() use ($identifier) {
				return $this->createModel()->newQuery()->find($identifier);
			}
		);
	}

	/**
	 * Retrieve a user by their unique identifier and "remember me" token.
	 *  - override -
	 *  with using cache.
	 *
	 * @param  mixed  $identifier
	 * @param  string  $token
	 * @return \Illuminate\Contracts\Auth\Authenticatable|null
	 */
	public function retrieveByToken($identifier, $token)
	{
		$model = $this->createModel();

		return cache()->remember($this->getModel() . '_By_Id_Token_' . $identifier, 60,
			function() use ($model, $identifier, $token) {
				return $model->newQuery()
					->where($model->getAuthIdentifierName(), $identifier)
					->where($model->getRememberTokenName(), $token)
					->first();
			}
		);
	}

	// キャッシュクリア
	public static function clearCache($model)
	{
		cache()->forget(get_class($model) . '_By_Id_' . $model->id);
		cache()->forget(get_class($model) . '_By_Id_Token_' . $model->id);
		cache()->forget(get_class($model) . '_By_Credentials_' . $model->{$model->authField});
	}

	/**
	 * Retrieve a user by the given credentials.
	 *
	 * @param  array  $credentials
	 * @return \Illuminate\Contracts\Auth\Authenticatable|null
	 */
	public function retrieveByCredentials(array $credentials)
	{
		if (empty($credentials)) {
			return;
		}
		$model = $this->createModel();

		return cache()->remember($this->getModel() . '_By_Credentials_'. $credentials[$model->authField], 60,
			function () use ($credentials) {
				// First we will add each credential element to the query as a where clause.
				// Then we can execute the query and, if we found a user, return it in a
				// Eloquent User "model" that will be utilized by the Guard instances.
				$query = $this->createModel()->newQuery();

				foreach ($credentials as $key => $value) {
					if (! Str::contains($key, 'password')) {
						$query->where($key, $value);
					}
				}

				return $query->first();
			}
		);

	}
}


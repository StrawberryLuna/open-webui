<script lang="ts">
	import { DropdownMenu } from 'bits-ui';
	import { flyAndScale } from '$lib/utils/transitions';
	import { getContext, createEventDispatcher } from 'svelte';
	import Dropdown from '$lib/components/common/Dropdown.svelte';
	import Tooltip from '$lib/components/common/Tooltip.svelte';
	import ArrowUpCircle from '$lib/components/icons/ArrowUpCircle.svelte';
	import Pencil from '$lib/components/icons/Pencil.svelte';
	import EllipsisHorizontal from '$lib/components/icons/EllipsisHorizontal.svelte';
	import GarbageBin from '$lib/components/icons/GarbageBin.svelte';
	import EventConfirmDialog from '../common/ConfirmDialog.svelte';
	import Search from '$lib/components/icons/Search.svelte'; // Search icon
	import { goto } from '$app/navigation';

	const i18n = getContext('i18n');
	const dispatch = createEventDispatcher();

	export let onClose: Function = () => {};
	let show = false;

	let searchQuery = '';
	let showConfirmDialog = false;
	let roleToDelete = null;

	// Temporary roles data, replace with database or API in the future
	let roles = [
		{ name: 'Admin', description: 'The root user' },
		{ name: 'Finance', description: 'Manages budgeting, financial planning, reporting, and resource allocation.' },
		{ name: 'Marketing', description: 'Promotes the brand, attracts customers, and boosts sales.' }
	];

	function confirmDelete() {
		if (roleToDelete) {
			roles = roles.filter(role => role.name !== roleToDelete);
			roleToDelete = null;
		}
		showConfirmDialog = false;
	}

	function openDeleteConfirm(roleName) {
		roleToDelete = roleName;
		showConfirmDialog = true;
	}
</script>

<style>
	.header {
		display: flex;
		align-items: center;
		margin-bottom: 16px;
		background-color: transparent; /* Matching background color */
	}
	.search-container {
		display: flex;
		align-items: center;
		width: 100%;
		padding: 8px;
		background-color: transparent; /* Matching background color */
		margin-right: 16px;
	}
	.search-icon {
		margin-right: 8px;
		color: #888;
	}
	.separator {
		height: 20px;
		width: 1px;
		background-color: #ddd;
		margin-right: 8px;
	}
	.search-input {
		width: 100%;
		border: none;
		background: transparent;
		outline: none;
		color: #555;
	}
	.role-list {
		margin-top: 16px;
	}
	.role-item {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 12px;
		border: 1px solid #ddd;
		border-radius: 8px;
		margin-bottom: 16px;
	}
	.role-info {
		flex: 1;
	}
	.role-name {
		font-weight: bold;
	}
	.role-description {
		color: #666;
		margin-top: 4px;
		font-size: 0.875rem;
	}
	.action-buttons {
		display: flex;
		align-items: center;
		gap: 8px;
	}
	.delete-icon {
		color: #ff0000;
	}
</style>

<div class="header">
	<div class="search-container">
		<Search class="search-icon w-5 h-5" />
		<div class="separator"></div>
		<input
			type="text"
			class="search-input"
			placeholder="Search Roles"
			bind:value={searchQuery}
		/>
	</div>

	<Tooltip content={$i18n.t('Add Content')}>
 	<button
 		class="p-1.5 rounded-xl hover:bg-gray-100 dark:bg-gray-850 dark:hover:bg-gray-800 transition font-medium text-sm flex items-center space-x-1"
 		on:click={() => goto('/path/to/role/edit')}
 	>
 		<svg
 			xmlns="http://www.w3.org/2000/svg"
 			viewBox="0 0 16 16"
 			fill="currentColor"
 			class="w-4 h-4"
 		>
 			<path
 				d="M8.75 3.75a.75.75 0 0 0-1.5 0v3.5h-3.5a.75.75 0 0 0 0 1.5h3.5v3.5a.75.75 0 0 0 1.5 0v-3.5h3.5a.75.75 0 0 0 0-1.5h-3.5v-3.5Z"
 			/>
 		</svg>
 	</button>
 </Tooltip>

</div>

<div class="role-list">
	{#each roles.filter(role => role.name.toLowerCase().includes(searchQuery.toLowerCase())) as role}
		<div class="role-item">
			<div class="role-info">
				<div class="role-name">{role.name}</div>
				<div class="role-description">{role.description}</div>
			</div>
			<div class="action-buttons">
				<div class="edit-button" on:click={() => goto('/path/to/role/edit')}>
					<Tooltip content={$i18n.t('Edit Role')}>
						<Pencil class="w-5 h-5 text-gray-500 hover:text-gray-800" />
					</Tooltip>
				</div>

				<Dropdown>
					<button class="p-1.5 rounded-full hover:bg-gray-100 dark:hover:bg-gray-850">
						<EllipsisHorizontal class="w-5 h-5 text-gray-500 hover:text-gray-800" />
					</button>
					<div slot="content">
						<DropdownMenu.Content
							class="w-full max-w-44 rounded-xl p-1 z-50 bg-white dark:bg-gray-850 dark:text-white shadow"
							sideOffset={4}
							side="bottom"
							align="end"
							transition={flyAndScale}
						>
							<DropdownMenu.Item
								class="flex gap-2 items-center px-3 py-2 text-sm cursor-pointer hover:bg-red-50 dark:hover:bg-red-800 rounded-md text-red-600"
								on:click={() => openDeleteConfirm(role.name)}
							>
								<GarbageBin class="w-4 h-4 delete-icon" />
								<div>Delete</div>
							</DropdownMenu.Item>
						</DropdownMenu.Content>
					</div>
				</Dropdown>
			</div>
		</div>
	{/each}
</div>

<EventConfirmDialog
	bind:show={showConfirmDialog}
	title={$i18n.t('Confirm your action')}
	message={$i18n.t('This action cannot be undone. Do you wish to continue?')}
	cancelLabel={$i18n.t('Cancel')}
	confirmLabel={$i18n.t('Confirm')}
	on:confirm={confirmDelete}
	on:cancel={() => {
		showConfirmDialog = false;
		roleToDelete = null;
	}}
/>